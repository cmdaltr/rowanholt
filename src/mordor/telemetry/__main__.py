"""python -m src.mordor.telemetry                 # what's built
   python -m src.mordor.telemetry --build         # fetch what the sources changed
   python -m src.mordor.telemetry --build --source otrf   # one source (splunk|otrf|evtx|macos|lab)
   python -m src.mordor.telemetry --guide <GUIDE zip, folder or CSV>   # Microsoft GUIDE (Defender XDR alerting)

Ported from Shikari. "lab" reads your own recordings (./lab.sh mordor-record). The Defender
export (mde.py) was left out: it depends on Shikari's Microsoft Graph setup.
"""

import argparse
import json
import os
import sys
import time

from . import datasets as ds

SOURCES = ("splunk", "otrf", "evtx", "macos", "lab")


def _module(name):
    if name == "splunk":
        from . import splunk_attack_data as m
    elif name == "evtx":
        from . import evtx_attack as m
    elif name == "macos":
        from . import macos_attack as m
    elif name == "lab":
        from . import lab as m
    else:
        from . import security_datasets as m
    return m


def build(sources=SOURCES, log=print) -> dict:
    """Fetch what changed since the last build and rewrite the summary and values."""
    try:
        with open(ds.STATE_PATH, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        state = {}
    old_values = ds.values() or {}
    summary = ds.load()
    keep = {d["id"]: d for d in summary["datasets"] if d["source"] not in sources}
    datasets, values = list(keep.values()), {k: v for k, v in old_values.items() if k in keep}
    info = {k: v for k, v in summary.get("sources", {}).items() if k not in sources}
    for name in sources:
        m = _module(name)
        fetched = reused = 0
        for summ, vals, key in m.datasets(state, log):
            if vals is None:
                if summ["id"] not in old_values:  # unchanged, but this machine has no values for it
                    state.pop(summ["id"], None)
                    continue
                vals, reused = old_values[summ["id"]], reused + 1
            else:
                fetched += 1
            datasets.append(summ)
            values[summ["id"]] = vals
            state[summ["id"]] = {"key": key, "summary": summ}
        info[name] = {**m.INFO, "built": time.strftime("%Y-%m-%d"),
                      "datasets": sum(1 for d in datasets if d["source"] == name)}
        log(f"{m.INFO['name']}: {fetched} fetched, {reused} unchanged")
    ds.save(datasets, values, info)
    os.makedirs(os.path.dirname(ds.STATE_PATH), exist_ok=True)
    with open(ds.STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    log(f"{len(datasets)} datasets, {len(ds.covered())} techniques")
    return ds.load()


def main(argv=None):
    p = argparse.ArgumentParser(description="Recorded attack telemetry (Splunk attack_data, Security-Datasets, EVTX-to-MITRE-Attack, macOS-ATTACK-DATASET, your lab)")
    p.add_argument("--build", action="store_true", help="download what changed and rebuild")
    p.add_argument("--source", choices=SOURCES, action="append", help="only this source (repeatable)")
    p.add_argument("--guide", metavar="PATH", help="summarise Microsoft's GUIDE dataset (the Kaggle zip, a folder or a CSV)")
    args = p.parse_args(argv)
    if args.guide:
        from . import guide

        guide.build(args.guide)
    elif args.build:
        build(tuple(args.source or SOURCES))
    else:
        s = ds.load()
        for name, info in s.get("sources", {}).items():
            print(f"{info['name']}: {info.get('datasets')} datasets, built {info.get('built')}")
        print(f"{len(ds.covered())} techniques; values here: {'yes' if ds.values() else 'no (run --build)'}")


if __name__ == "__main__":
    sys.exit(main())
