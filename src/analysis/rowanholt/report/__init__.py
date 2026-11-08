"""Case reports (FR-07): a report built from a finished case directory, in Markdown and DOCX.

- ``gather``: reads the case, read-only, never ``raw/``: hosts and timespan, ATT&CK techniques
  with the rows behind each, indicators, Gandalf's integrity check and Elrond's method.
- ``document``: the report as blocks, written out as Markdown or as DOCX (stdlib WordprocessingML).
- ``build``: the uncurated report from the case alone (Elrond's ``--Report``), and the curated one,
  the analysts' confirmed findings first and the rest as appendices (the web app's case browser).
- ``method``: what Elrond writes into the case for the report's method section: its options and
  the versions of the tools it found.

Stdlib only: the web backend loads this package by path from Elrond's source tree, as it loads
``rowanholt/core/records.py``.
"""

from .build import curated_report, uncurated_report, write_reports
from .gather import CaseReport, gather

__all__ = ["CaseReport", "curated_report", "gather", "uncurated_report", "write_reports"]
