"""Unit tests for a team server's licence (src/web/backend/licence.py): the shared format, standing,
seats and the shipped terms, without the backend. Licences are signed with a throwaway key.

Run: python3 -m unittest tests/unit/test_licence_units.py (needs cryptography)
"""

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "web" / "backend"))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import licence
except ImportError:  # cryptography not installed
    licence = None

TODAY = date(2026, 11, 11)


def at(day: date, hour: int = 12) -> datetime:
    return datetime(day.year, day.month, day.day, hour, tzinfo=timezone.utc)


def lic(edition="pro", seats=10, expires=date(2027, 11, 30), **extra):
    return licence.Licence("lic_test", "Northwind Ltd", licence.Edition(edition), seats, TODAY, expires, **extra)


def users(active: int, disabled: int = 0) -> dict:
    out = {f"a{i}": {"is_active": True} for i in range(active)}
    out.update({f"d{i}": {"is_active": False} for i in range(disabled)})
    return out


@unittest.skipIf(licence is None, "cryptography not installed")
class SigningTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        patch = mock.patch.object(licence, "PUBLIC_KEYS", (public,))
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_signed_licence_reads_back_exactly(self):
        original = lic("services", seats=None, expires=None, email="ops@northwind.example",
                       features=("*",), not_before=date(2026, 12, 1))
        self.assertEqual(licence.parse(licence.sign(self.key, original)), original)

    def test_the_payload_is_canonical_json_with_the_product(self):
        head, payload, _ = licence.sign(self.key, lic()).split(".")
        self.assertEqual(head, "rowanholt-licence-1")
        text = base64.urlsafe_b64decode(payload + "==").decode()
        self.assertEqual(text, json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")))
        self.assertEqual(json.loads(text)["product"], "rowanholt")

    def test_a_licence_for_another_product_is_refused(self):
        with self.assertRaisesRegex(licence.LicenceProblem, "licence for shikari"):
            licence.parse(licence.sign(self.key, lic(product="shikari")))

    def test_another_format_version_is_refused(self):
        _, payload, signature = licence.sign(self.key, lic()).split(".")
        with self.assertRaisesRegex(licence.LicenceProblem, "isn't a Rowanholt licence"):
            licence.parse(f"rowanholt-licence-2.{payload}.{signature}")

    def test_an_edited_licence_is_refused(self):
        head, payload, signature = licence.sign(self.key, lic(seats=10)).split(".")
        more = json.loads(base64.urlsafe_b64decode(payload + "=="))
        more["seats"] = 500
        forged = base64.urlsafe_b64encode(json.dumps(more).encode()).rstrip(b"=").decode()
        with self.assertRaisesRegex(licence.LicenceProblem, "altered"):
            licence.parse(f"{head}.{forged}.{signature}")

    def test_a_licence_signed_by_another_key_is_refused(self):
        with self.assertRaisesRegex(licence.LicenceProblem, "altered"):
            licence.parse(licence.sign(Ed25519PrivateKey.generate(), lic()))

    def test_text_that_isnt_a_licence_is_refused(self):
        for text in ("", "hello", "a.b", "rowanholt-licence-1.!!.!!"):
            with self.subTest(text=text), self.assertRaises(licence.LicenceProblem):
                licence.parse(text)

    def test_a_free_licence_grants_nothing(self):
        with self.assertRaisesRegex(licence.LicenceProblem, "nothing beyond the free edition"):
            licence.parse(licence.sign(self.key, lic("free")))


@unittest.skipIf(licence is None, "cryptography not installed")
class StandingTest(unittest.TestCase):
    def test_the_shipped_key_is_a_real_ed25519_public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        self.assertTrue(licence.PUBLIC_KEYS)
        for key in licence.PUBLIC_KEYS:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))

    def test_no_licence_is_the_free_edition_with_four_places(self):
        st = licence.standing(None)
        self.assertEqual((st.edition, st.seats, st.state), (licence.Edition.FREE, 4, "free"))

    def test_a_licence_runs_to_the_end_of_its_last_day_then_thirty_days_grace(self):
        one = lic(expires=date(2027, 11, 30))
        self.assertEqual(licence.standing(one, at(date(2027, 11, 30), 23)).state, "active")
        grace = licence.standing(one, at(date(2027, 12, 1)))
        self.assertEqual((grace.state, grace.edition, grace.seats), ("grace", licence.Edition.PRO, 10))
        self.assertEqual(licence.standing(one, at(date(2027, 12, 30))).state, "grace")
        lapsed = licence.standing(one, at(date(2027, 12, 31)))
        self.assertEqual((lapsed.state, lapsed.edition, lapsed.seats), ("lapsed", licence.Edition.FREE, 4))

    def test_grace_ends_thirty_days_after_expiry(self):
        self.assertEqual(licence.grace_ends(lic(expires=date(2027, 11, 30))), date(2027, 12, 30))
        self.assertIsNone(licence.grace_ends(lic(expires=None)))

    def test_a_licence_waits_for_its_first_day_and_a_perpetual_one_never_ends(self):
        later = lic(not_before=date(2026, 12, 1))
        pending = licence.standing(later, at(date(2026, 11, 30), 23))
        self.assertEqual((pending.state, pending.edition), ("pending", licence.Edition.FREE))
        self.assertEqual(licence.standing(later, at(date(2026, 12, 1), 0)).state, "active")
        self.assertEqual(licence.standing(lic(expires=None), at(date(2099, 1, 1))).state, "active")

    def test_the_editions_features_are_the_shared_table(self):
        L = licence
        self.assertEqual(L.EDITION_FEATURES[L.Edition.FREE], frozenset())
        self.assertEqual(L.EDITION_FEATURES[L.Edition.PRO], {L.REPORT_BRANDING, L.AUTOMATION})
        self.assertEqual(L.EDITION_FEATURES[L.Edition.SERVICES],
                         {L.REPORT_BRANDING, L.AUTOMATION, L.BRAND_LIBRARY, L.MANAGED_SERVICE})
        free, pro, services = (L.standing(None), L.standing(lic("pro"), at(TODAY)),
                               L.standing(lic("services"), at(TODAY)))
        self.assertFalse(any(free.has(f) for f in L.FEATURES))
        self.assertTrue(pro.has(L.REPORT_BRANDING) and pro.has(L.AUTOMATION) and not pro.has(L.BRAND_LIBRARY))
        self.assertTrue(all(services.has(f) for f in L.FEATURES))

    def test_an_edition_grants_its_features_and_a_licence_can_add_more(self):
        self.assertFalse(licence.standing(lic("pro"), at(TODAY)).has(licence.MANAGED_SERVICE))
        self.assertTrue(licence.standing(lic("services"), at(TODAY)).has(licence.MANAGED_SERVICE))
        self.assertTrue(licence.standing(lic("pro", features=("extra",)), at(TODAY)).has("extra"))
        everything = licence.standing(lic("pro", features=("*",)), at(TODAY))
        self.assertTrue(everything.has(licence.MANAGED_SERVICE) and everything.has("anything"))
        lapsed = licence.standing(lic("services"), at(date(2028, 6, 1)))
        self.assertFalse(lapsed.has(licence.MANAGED_SERVICE))


@unittest.skipIf(licence is None, "cryptography not installed")
class InstalledTest(unittest.TestCase):
    """The installed file and the seat rule, with ROWANHOLT_LICENCE pointing at a temporary file."""

    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        for patch in (mock.patch.object(licence, "PUBLIC_KEYS", (public,)),
                      mock.patch.dict(os.environ, {"ROWANHOLT_LICENCE": f"{tempfile.mkdtemp()}/licence.json"})):
            patch.start()
            self.addCleanup(patch.stop)

    def install(self, one):
        return licence.record_install(licence.sign(self.key, one), accepted_by="u1",
                                      accepted_by_name="Ada Admin <ada@example.org>")

    def test_the_free_edition_has_four_places_and_refuses_a_fifth(self):
        self.assertIsNone(licence.seat_refusal(users(3), server_mode=True))
        self.assertIn("All 4 places on the free edition are taken", licence.seat_refusal(users(4), server_mode=True))

    def test_disabled_accounts_hold_no_place(self):
        self.assertIsNone(licence.seat_refusal(users(3, disabled=5), server_mode=True))

    def test_local_mode_is_never_limited(self):
        self.assertIsNone(licence.seat_refusal(users(50), server_mode=False))

    def test_local_mode_reads_as_free_with_no_licence_and_as_pro_with_one(self):
        # One analyst, no sign-in: the same standing as a server's, with no seat check
        self.assertEqual(licence.current().edition, licence.Edition.FREE)
        self.assertFalse(licence.current().has(licence.REPORT_BRANDING))
        self.install(lic("pro"))
        self.assertEqual(licence.current().edition, licence.Edition.PRO)
        self.assertTrue(licence.current().has(licence.REPORT_BRANDING) and licence.current().has(licence.AUTOMATION))
        self.assertIsNone(licence.seat_refusal(users(50), server_mode=False))

    def test_seats_come_from_the_licence_and_unlimited_never_refuses(self):
        self.install(lic(seats=6))
        self.assertIsNone(licence.seat_refusal(users(5), server_mode=True))
        self.assertIn("this pro licence", licence.seat_refusal(users(6), server_mode=True))
        self.install(lic(seats=None))
        self.assertIsNone(licence.seat_refusal(users(500), server_mode=True))

    def test_the_install_keeps_the_terms_version_and_who_accepted(self):
        record = self.install(lic())
        stored = json.loads(Path(os.environ["ROWANHOLT_LICENCE"]).read_text())
        self.assertEqual(stored, record)
        self.assertEqual(stored["terms_version"], licence.terms()[0])
        self.assertEqual((stored["accepted_by"], stored["accepted_by_name"]), ("u1", "Ada Admin <ada@example.org>"))
        self.assertEqual(oct(Path(os.environ["ROWANHOLT_LICENCE"]).stat().st_mode & 0o777), "0o600")

    def test_installing_again_is_seen_and_removing_goes_back_to_free(self):
        self.install(lic("pro"))
        self.assertEqual(licence.current().edition, licence.Edition.PRO)
        time.sleep(0.01)  # a new mtime, so the cache sees the second file
        self.install(lic("services"))
        self.assertEqual(licence.current().edition, licence.Edition.SERVICES)
        self.assertTrue(licence.remove())
        self.assertEqual(licence.current().state, "free")
        self.assertFalse(licence.remove())

    def test_a_damaged_or_unverifiable_file_counts_as_no_licence(self):
        path = Path(os.environ["ROWANHOLT_LICENCE"])
        path.write_text("{not json")
        self.assertEqual(licence.current().state, "free")
        time.sleep(0.01)
        path.write_text(json.dumps({"licence": licence.sign(Ed25519PrivateKey.generate(), lic())}))
        self.assertEqual(licence.current().state, "free")

    def test_a_lapsed_licence_never_takes_a_place_from_anyone_already_in(self):
        # Ten people were added under a licence that has now lapsed: they all stay, only an eleventh is refused
        self.install(lic(seats=10, expires=date(2026, 1, 1)))
        self.assertEqual(licence.current().state, "lapsed")
        self.assertIsNotNone(licence.seat_refusal(users(10), server_mode=True))
        self.assertEqual(licence.places_held(users(10)), 10)


@unittest.skipIf(licence is None, "cryptography not installed")
class SignerTest(unittest.TestCase):
    """scripts/admin/sign_licence.py with a throwaway key, into a throwaway ledger."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("sign_licence", ROOT / "scripts" / "admin" / "sign_licence.py")
        self.signer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.signer)
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.ledger = Path(tempfile.mkdtemp())
        (self.ledger / "ledger.csv").write_text(",".join(self.signer.LEDGER_FIELDS) + "\n")
        # The licence module the signer imported: another test file may have reloaded the backend's
        self.licence = self.signer.licence
        for patch in (mock.patch.object(self.licence, "PUBLIC_KEYS", (public,)),
                      mock.patch.dict(os.environ, {"ROWANHOLT_LICENCE_KEY": seed, "LICENCE_LEDGER_DIR": str(self.ledger)})):
            patch.start()
            self.addCleanup(patch.stop)

    def run_signer(self, *argv):
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["sign_licence.py", *argv]), redirect_stdout(out):
            self.assertEqual(self.signer.main(), 0)
        return out.getvalue().strip().splitlines()

    def test_signing_files_the_licence_and_a_ledger_row_with_the_terms_version(self):
        lines = self.run_signer("sign", "--licensee", "Northwind Ltd", "--edition", "services", "--seats", "25",
                                "--expires", "2099-11-30", "--email", "ops@northwind.example")
        line = lines[-1]
        parsed = self.licence.parse(line)
        self.assertEqual((parsed.product, parsed.edition.value, parsed.seats), ("rowanholt", "services", 25))
        filed = self.ledger / "issued" / "rowanholt" / f"{parsed.licence_id}.licence"
        self.assertEqual(filed.read_text().strip(), line)
        import csv
        rows = list(csv.DictReader((self.ledger / "ledger.csv").open()))
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["licence_id"], rows[0]["product"], rows[0]["seats"], rows[0]["terms_version"],
                          rows[0]["file"]),
                         (parsed.licence_id, "rowanholt", "25", "1.1", f"issued/rowanholt/{parsed.licence_id}.licence"))

    def test_keygen_refuses_to_overwrite_a_key(self):
        path = self.ledger / "key.pem"
        public = self.run_signer("keygen", str(path))[0]
        self.assertEqual(len(bytes.fromhex(public)), 32)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        with mock.patch.object(sys, "argv", ["sign_licence.py", "keygen", str(path)]), self.assertRaises(FileExistsError):
            self.signer.main()


@unittest.skipIf(licence is None, "cryptography not installed")
class TermsTest(unittest.TestCase):
    def test_the_terms_rowanholt_ships_are_the_terms_in_the_repo(self):
        self.assertEqual(licence.TERMS.read_text(), (ROOT / "COMMERCIAL-LICENSE.md").read_text(),
                         "copy COMMERCIAL-LICENSE.md to src/web/backend/legal/")

    def test_the_licence_the_web_ui_shows_is_the_licence_in_the_repo(self):
        self.assertEqual((ROOT / "src/web/frontend/public/LICENSE.txt").read_text(), (ROOT / "LICENSE").read_text(),
                         "copy LICENSE to src/web/frontend/public/LICENSE.txt")

    def test_the_terms_state_their_version(self):
        version, text = licence.terms()
        self.assertEqual(version, "1.1")
        self.assertIn("**Version 1.1**", text.splitlines()[2])


if __name__ == "__main__":
    unittest.main()
