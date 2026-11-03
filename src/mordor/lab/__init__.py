"""
Mordor lab: create and manage the containers and VMs a recording runs on, from Dernvale's
Mordor page. Ported from Archer's archer.lab. The Dernvale lab agent (lab/agent/lab_agent.py)
runs it on the host, because the backend's container can't reach Docker, Tart or UTM there.

It drives what's on the machine it runs on: Docker (or OrbStack) for Linux containers, Tart
for macOS and Linux VMs on Apple Silicon, UTM for Windows. It is OS- and architecture-aware: a
template is only offered when the host can run it, and a template's image is chosen for the
host's architecture. Hypervisors aren't installed for you; the host card shows the exact
command when one is missing.

The pieces:
  hosts       what this machine is and which engines it has
  templates   the machines you can create here, filtered to the host
  machines    create, start, stop, snapshot, revert, clone, delete, status, logs
  provision   turn logging on and install Atomic Red Team in a machine
  record      run Atomic Red Team in a machine and import the recording (src.mordor.telemetry)
  iso         check a Windows ISO is an ARM64 installer before a VM is built from it

Everything goes through runner.run, one place that shells out, so the logic above it is tested
without a hypervisor.
"""

from .runner import LabError, run  # noqa: F401
