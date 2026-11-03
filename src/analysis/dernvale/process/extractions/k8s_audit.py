"""Kubernetes API server audit logs (audit.k8s.io/v1 Event, one JSON object per line), from a
control-plane node's /var/log/kubernetes/ or an export from EKS, AKS or GKE.

One row per request at the ResponseComplete stage (or the only stage logged), flagged where the
request is something an intruder does with a cluster: reading secrets, exec into pods, granting
cluster roles, minting service-account tokens, scheduling jobs, deploying privileged pods, and
discovery from an identity that isn't a Kubernetes component.
"""

import json
from typing import Dict, Iterable, List, Optional, Tuple

HEADER = ["LastWriteTime", "User", "Groups", "SourceIPs", "UserAgent", "Verb", "Resource", "Subresource",
          "Namespace", "Name", "Status", "Flag", "Technique"]

ADMIN_ROLES = ("cluster-admin", "admin", "edit", "system:masters")
DISCOVERY_RESOURCES = {"pods", "nodes", "namespaces", "deployments", "daemonsets", "services", "serviceaccounts",
                       "roles", "clusterroles", "rolebindings", "clusterrolebindings", "configmaps"}


def _component(user: str) -> bool:
    """Kubernetes' own identities: nodes, controllers and the control plane."""
    return user.startswith(("system:node:", "system:kube-", "system:serviceaccount:kube-system:")) or \
        user in ("system:apiserver", "system:kube-scheduler", "system:kube-controller-manager")


def _privileged_pod(spec: Dict) -> List[str]:
    flags = []
    for key, what in (("hostPID", "host PID namespace"), ("hostNetwork", "host network"), ("hostIPC", "host IPC")):
        if spec.get(key):
            flags.append(what)
    for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        if ((container.get("securityContext") or {}).get("privileged")):
            flags.append("privileged container")
    for volume in spec.get("volumes") or []:
        path = (volume.get("hostPath") or {}).get("path")
        if path:
            flags.append(f"hostPath {path}")
    return flags


def classify(event: Dict) -> Tuple[str, str]:
    """(flag, technique) for one audit event, or ('', '') for an unremarkable one."""
    user = (event.get("user") or {}).get("username", "")
    verb = event.get("verb", "")
    ref = event.get("objectRef") or {}
    resource, sub = ref.get("resource", ""), ref.get("subresource", "")
    code = (event.get("responseStatus") or {}).get("code", 0)
    ok = not code or 200 <= int(code) < 300
    if not ok:
        if user == "system:anonymous":
            return "anonymous request refused", "T1613"
        return "", ""
    if user == "system:anonymous":
        return "anonymous request allowed", "T1078.001"
    if resource == "secrets" and verb in ("get", "list", "watch") and not _component(user):
        return "secrets read", "T1552.007"
    if resource == "pods" and sub in ("exec", "attach") and verb in ("create", "get"):
        return f"{sub} into a pod", "T1609"
    if resource == "serviceaccounts" and sub == "token" and verb == "create" and not _component(user):
        return "service account token created", "T1528"
    if resource in ("clusterrolebindings", "rolebindings") and verb in ("create", "update", "patch"):
        role = ((event.get("requestObject") or {}).get("roleRef") or {}).get("name", "")
        if role in ADMIN_ROLES or not role:
            return f"role binding {verb}d" + (f" to {role}" if role else ""), "T1098.006"
    if resource in ("cronjobs", "jobs") and verb == "create" and not _component(user):
        return f"{resource[:-1]} created", "T1053.007"
    if resource == "pods" and verb == "create" and not sub:
        flags = _privileged_pod((event.get("requestObject") or {}).get("spec") or {})
        if flags:
            return "pod created with " + ", ".join(flags), "T1611"
        if not _component(user):
            return "pod created", "T1610"
    if resource in ("daemonsets", "deployments") and verb == "create" and not _component(user):
        spec = (((event.get("requestObject") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        flags = _privileged_pod(spec)
        return f"{resource[:-1]} created" + (" with " + ", ".join(flags) if flags else ""), \
            "T1611" if flags else "T1610"
    if verb == "list" and resource in DISCOVERY_RESOURCES and not ref.get("namespace") and not _component(user) \
            and not user.startswith("system:serviceaccount:"):
        return f"cluster-wide list of {resource}", "T1613"
    return "", ""


def events(path: str) -> Iterable[Dict]:
    """Audit events from JSON lines (the API server's own log), a JSON array, or a {"items": [...]}
    export. A JSON-lines file fails to parse as one document at its second line, which is cheap."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError:
        for line in text.splitlines():
            try:
                yield json.loads(line)
            except ValueError:
                continue
        return
    if isinstance(data, list):
        yield from data
    elif isinstance(data, dict):
        yield from data.get("items", [data])


def looks_like_audit_log(path: str) -> bool:
    try:
        event = next(iter(events(path)), None)
    except (OSError, ValueError):
        return False
    return isinstance(event, dict) and event.get("apiVersion", "").startswith("audit.k8s.io/")


def audit_rows(path: str) -> List[Dict[str, str]]:
    rows = []
    for event in events(path):
        if not isinstance(event, dict) or event.get("stage", "ResponseComplete") not in ("ResponseComplete", "Panic"):
            continue
        user = event.get("user") or {}
        ref = event.get("objectRef") or {}
        flag, technique = classify(event)
        rows.append({
            "LastWriteTime": event.get("requestReceivedTimestamp") or event.get("stageTimestamp", ""),
            "User": user.get("username", ""), "Groups": ", ".join(user.get("groups") or []),
            "SourceIPs": ", ".join(event.get("sourceIPs") or []), "UserAgent": event.get("userAgent", ""),
            "Verb": event.get("verb", ""), "Resource": ref.get("resource", ""),
            "Subresource": ref.get("subresource", ""), "Namespace": ref.get("namespace", ""),
            "Name": ref.get("name", ""), "Status": str((event.get("responseStatus") or {}).get("code", "")),
            "Flag": flag, "Technique": technique,
        })
    return rows


def audit_techniques(rows: List[Dict[str, str]]) -> List[str]:
    return sorted({r["Technique"] for r in rows if r["Technique"]})


def summary(rows: List[Dict[str, str]]) -> Optional[Dict]:
    """Counts for a report: events, flagged events, and techniques with their flags."""
    if not rows:
        return None
    flagged = [r for r in rows if r["Flag"]]
    by_technique: Dict[str, List[str]] = {}
    for row in flagged:
        by_technique.setdefault(row["Technique"], []).append(f"{row['LastWriteTime']} {row['User']}: {row['Flag']}")
    return {"total_events": len(rows), "flagged_events": len(flagged), "techniques": by_technique}
