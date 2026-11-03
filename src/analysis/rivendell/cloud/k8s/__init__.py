"""Kubernetes: API server audit logs exported from a cluster (EKS, AKS, GKE or self-managed).

Parsing is shared with Elrond's node collection: process/extractions/k8s_audit.py.
"""

from .audit import analyse_audit_log

__all__ = ["analyse_audit_log"]
