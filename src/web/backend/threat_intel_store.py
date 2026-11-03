"""Threat intelligence indicators in Postgres (threat_intel_indicators), for the API and the worker.

Parsing and matching live with Elrond, in rivendell/threat_intel/: the backend mounts that
package (docker-compose.yml) and finds it through elrond_src(), as Mordor's routes find
src/mordor. The worker image has it already, at /opt/elrond-src.

Each indicator's expiry is in threat_intel_validity beside it (rivendell/threat_intel/validity.py):
expired indicators stay listed, marked, but are left out of what Elrond matches (export_csv) and
what Eru and /enrich check (indicators()), until a refreshed import or an admin brings them back.
"""

import logging
import os
import sys
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import and_, func, or_

try:
    from .storage import ThreatIntelIndicatorModel, ThreatIntelValidityModel
except ImportError:
    from storage import ThreatIntelIndicatorModel, ThreatIntelValidityModel

logger = logging.getLogger(__name__)

ELROND_SRC = os.environ.get("RIVENDELL_ELROND_SRC", "/opt/elrond-src")
FIELDS = ("evidential_element", "threat_group", "procedure_example", "technique_id", "technique_name", "tactic",
          "contextual_evidence", "reference_url", "navigation_layer_url", "source_type")
INSERT_BATCH = 2000
Validity = ThreatIntelValidityModel


class ThreatIntelUnavailable(RuntimeError):
    """rivendell/threat_intel isn't importable here."""


def threat_intel():
    """The rivendell.threat_intel package, from Elrond's source tree."""
    if ELROND_SRC not in sys.path:
        sys.path.append(ELROND_SRC)  # appended: /app's modules keep priority
    try:
        import rivendell.threat_intel as package
        import rivendell.threat_intel.match  # noqa: F401 (the worker's export uses the package as a whole)
    except ImportError as exc:
        raise ThreatIntelUnavailable(f"rivendell/threat_intel not found under {ELROND_SRC}: {exc}") from exc
    return package


def validity_module():
    """rivendell.threat_intel.validity, from Elrond's source tree."""
    threat_intel()
    import rivendell.threat_intel.validity as module
    return module


def _expired_filter(now: datetime):
    return and_(Validity.valid_until.isnot(None), Validity.valid_until <= now)


class ThreatIntelStore:
    """Indicators in the database. Takes a SQLAlchemy session factory (JobStorage.Session)."""

    def __init__(self, session_factory):
        self.Session = session_factory

    def counts(self) -> Dict:
        with self.Session() as session:
            total = session.query(func.count(ThreatIntelIndicatorModel.id)).scalar() or 0
            sources = session.query(ThreatIntelIndicatorModel.source_type, func.count(ThreatIntelIndicatorModel.id)) \
                .group_by(ThreatIntelIndicatorModel.source_type).order_by(ThreatIntelIndicatorModel.source_type).all()
            groups = session.query(func.count(func.distinct(ThreatIntelIndicatorModel.threat_group))) \
                .filter(ThreatIntelIndicatorModel.threat_group != "").scalar() or 0
        return {"total": total, "groups": groups, "expired": self.expired_count(),
                "sources": [{"source": s or "", "count": n} for s, n in sources]}

    def expired_count(self, now: Optional[datetime] = None) -> int:
        """Indicators past their valid_until, which matching leaves out."""
        now = now or validity_module().utcnow()
        with self.Session() as session:
            return session.query(func.count(Validity.indicator_id)).filter(_expired_filter(now)).scalar() or 0

    def version(self) -> Tuple[int, int, int]:
        """(rows, highest id, expired): changes whenever indicators are added or removed, or expire or come back."""
        with self.Session() as session:
            return (session.query(func.count(ThreatIntelIndicatorModel.id)).scalar() or 0,
                    session.query(func.max(ThreatIntelIndicatorModel.id)).scalar() or 0,
                    self.expired_count())

    def search(self, query: str = "", source: str = "", limit: int = 100, offset: int = 0) -> Dict:
        with self.Session() as session:
            rows = session.query(ThreatIntelIndicatorModel)
            if source:
                rows = rows.filter(ThreatIntelIndicatorModel.source_type == source)
            if query:
                like = f"%{query}%"
                rows = rows.filter(or_(ThreatIntelIndicatorModel.evidential_element.ilike(like),
                                       ThreatIntelIndicatorModel.threat_group.ilike(like),
                                       ThreatIntelIndicatorModel.technique_id.ilike(like)))
            total = rows.count()
            page = rows.order_by(ThreatIntelIndicatorModel.id).offset(offset).limit(min(limit, 500)).all()
            held = {v.indicator_id: v for v in session.query(Validity).filter(Validity.indicator_id.in_([r.id for r in page]))}
            now = validity_module().utcnow()
            out = []
            for r in page:
                v = held.get(r.id)
                until = v.valid_until if v else None
                out.append({"id": r.id, **{f: getattr(r, f) or "" for f in FIELDS},
                            "valid_until": until.isoformat() if until else None,
                            "confidence": v.confidence if v else None,
                            "first_seen": v.first_seen.isoformat() if v and v.first_seen else None,
                            "expired": bool(until and until <= now)})
            return {"total": total, "indicators": out}

    def add(self, indicators: Iterable, validity: Optional[Dict[tuple, object]] = None,
            now: Optional[datetime] = None) -> Tuple[int, int]:
        """(added, already there): an indicator already stored under the same key is skipped, but its
        validity is renewed, so a refreshed import brings back what had expired. `validity` is a STIX
        bundle's own (by key, from load_with_validity); the rest get the default lifetime from now."""
        indicators = list(indicators)
        validity = validity or {}
        lifetimes = validity_module()
        now = now or lifetimes.utcnow()
        sources = {i.source_type for i in indicators}
        with self.Session() as session:
            existing: Dict[tuple, int] = {}
            for row in session.query(ThreatIntelIndicatorModel.id, *[getattr(ThreatIntelIndicatorModel, f) for f in
                                       ("evidential_element", "threat_group", "technique_id", "source_type")]) \
                    .filter(ThreatIntelIndicatorModel.source_type.in_(sources)):
                existing[((row[1] or "").lower(), (row[2] or "").lower(), (row[3] or "").upper(), (row[4] or "").lower())] = row[0]
            new, keys, renewed = [], [], {}
            for indicator in indicators:
                key = indicator.key()
                if key in existing:
                    renewed[existing[key]] = indicator
                    continue
                existing[key] = 0
                new.append({f: getattr(indicator, f) for f in FIELDS})
                keys.append(indicator)
            for start in range(0, len(new), INSERT_BATCH):
                # return_defaults fills in each new row's id, which its validity row is keyed by
                session.bulk_insert_mappings(ThreatIntelIndicatorModel, new[start:start + INSERT_BATCH], return_defaults=True)
            held = {**{mapping["id"]: indicator for mapping, indicator in zip(new, keys)}, **renewed}
            self._hold(session, held, validity, lifetimes, now)
            session.commit()
        return len(new), len(indicators) - len(new)

    @staticmethod
    def _hold(session, held: Dict[int, object], validity: Dict[tuple, object], lifetimes, now: datetime) -> None:
        """Write the validity of these indicators (by id): their own, or the default lifetime from now."""
        rows = {}
        for indicator_id, indicator in held.items():
            v = validity.get(indicator.key()) or lifetimes.default_validity(indicator, now)
            if v.valid_until is not None or v.confidence is not None:
                rows[indicator_id] = v
        if not rows:
            return
        ids = list(rows)
        stored = {}
        for start in range(0, len(ids), INSERT_BATCH):
            stored.update({v.indicator_id: v.first_seen for v in session.query(Validity)
                           .filter(Validity.indicator_id.in_(ids[start:start + INSERT_BATCH]))})
        inserts = [{"indicator_id": i, "valid_until": v.valid_until, "confidence": v.confidence,
                    "first_seen": v.first_seen or now} for i, v in rows.items() if i not in stored]
        updates = [{"indicator_id": i, "valid_until": v.valid_until, "confidence": v.confidence,
                    "first_seen": stored[i] or v.first_seen or now} for i, v in rows.items() if i in stored]
        for start in range(0, len(inserts), INSERT_BATCH):
            session.bulk_insert_mappings(Validity, inserts[start:start + INSERT_BATCH])
        for start in range(0, len(updates), INSERT_BATCH):
            session.bulk_update_mappings(Validity, updates[start:start + INSERT_BATCH])

    def set_validity(self, indicator_id: int, valid_until: Optional[datetime]) -> Dict:
        """An admin's extension (a new valid_until) or clearing (None: no expiry) of one indicator."""
        with self.Session() as session:
            if session.get(ThreatIntelIndicatorModel, indicator_id) is None:
                raise KeyError(indicator_id)
            row = session.get(Validity, indicator_id)
            if row is None:
                row = Validity(indicator_id=indicator_id, first_seen=validity_module().utcnow())
                session.add(row)
            row.valid_until = valid_until
            session.commit()
            return {"id": indicator_id, "valid_until": valid_until.isoformat() if valid_until else None,
                    "confidence": row.confidence}

    def delete_source(self, source: str) -> int:
        with self.Session() as session:
            ids = session.query(ThreatIntelIndicatorModel.id).filter(ThreatIntelIndicatorModel.source_type == source)
            session.query(Validity).filter(Validity.indicator_id.in_(ids.scalar_subquery())) \
                .delete(synchronize_session=False)
            removed = session.query(ThreatIntelIndicatorModel).filter(ThreatIntelIndicatorModel.source_type == source) \
                .delete(synchronize_session=False)
            session.commit()
        return removed

    def indicators(self, include_expired: bool = False, now: Optional[datetime] = None) -> List:
        """The stored indicators that haven't expired (or every one), as rivendell.threat_intel Indicators."""
        Indicator = threat_intel().Indicator
        now = now or validity_module().utcnow()
        with self.Session() as session:
            rows = session.query(ThreatIntelIndicatorModel)
            if not include_expired:
                rows = rows.outerjoin(Validity, Validity.indicator_id == ThreatIntelIndicatorModel.id) \
                    .filter(or_(Validity.valid_until.is_(None), Validity.valid_until > now))
            return [Indicator(**{f: getattr(r, f) or "" for f in FIELDS}) for r in rows.yield_per(5000)]

    def export_csv(self, path: str) -> int:
        """Every indicator that hasn't expired, as the CSV Elrond's --threatIntel reads."""
        from rivendell.threat_intel.schema import write_csv  # threat_intel() put it on the path
        return write_csv(path, self.indicators())


_store: Optional[ThreatIntelStore] = None


def configure(storage) -> None:
    """Give the store the backend's JobStorage (main.py does, beside access.configure)."""
    global _store
    _store = ThreatIntelStore(storage.Session)


def store() -> ThreatIntelStore:
    if _store is None:
        raise RuntimeError("threat_intel_store.configure() hasn't been called")
    return _store
