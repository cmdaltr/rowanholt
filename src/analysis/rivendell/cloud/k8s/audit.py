"""Kubernetes audit log analysis for the cloud CLI: the same rows and techniques as a node's
collected audit log, written as k8s_audit.csv and a JSON summary beside it."""

import csv
import json
import os
from typing import Dict

from rivendell.process.extractions import k8s_audit


def analyse_audit_log(log_file: str, output_dir: str) -> Dict:
    """Parse one exported audit log into output_dir; returns the summary."""
    rows = k8s_audit.audit_rows(log_file)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "k8s_audit.csv"), "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=k8s_audit.HEADER)
        writer.writeheader()
        writer.writerows(rows)
    summary = k8s_audit.summary(rows) or {"total_events": 0, "flagged_events": 0, "techniques": {}}
    with open(os.path.join(output_dir, "k8s_audit_analysis.json"), "w", encoding="utf-8") as out:
        json.dump(summary, out, indent=1)
    return summary
