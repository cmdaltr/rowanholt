#!/usr/bin/env python3
"""QEMU's control socket (QMP) for qemu-vm.sh, and its memory dumps as raw images.

    qmp.py <socket> <command> ['<json arguments>']   run one command, print its return as JSON
    qmp.py <socket> keys <key> <count> [<seconds>]   press a key <count> times (the ISO's boot prompt)
    qmp.py <socket> backup <device> <target.qcow2>   a full point-in-time copy of a disk, waited for
    qmp.py elf2raw <dump.elf> <memory.mem>           dump-guest-memory's ELF core as a raw image

A raw image is a file whose offsets are physical addresses, the format every memory tool
reads; the gaps between RAM ranges (below 4 GB on a PC) are left as holes. Python 3.8+,
stdlib only (the lab's host-side rule).
"""
import json
import socket
import struct
import sys
import time
from typing import Any, Dict, Optional


class QMPError(Exception):
    """QEMU refused a command or the socket closed."""


class QMP:
    """One QMP session: the greeting, capabilities negotiation, then commands."""

    def __init__(self, path: str) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.buf = b""
        self.events = []
        self._read()  # the greeting
        self.run("qmp_capabilities")

    def _read(self) -> Dict[str, Any]:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise QMPError("QEMU closed the control socket")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def run(self, command: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        message = {"execute": command}
        if arguments:
            message["arguments"] = arguments
        self.sock.sendall(json.dumps(message).encode() + b"\n")
        while True:
            reply = self._read()
            if "event" in reply:
                self.events.append(reply)
            elif "error" in reply:
                raise QMPError(f"{command}: {reply['error'].get('desc', reply['error'])}")
            elif "return" in reply:
                return reply["return"]

    def wait_event(self, name: str, timeout: float) -> Dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for event in self.events:
                if event["event"] == name:
                    self.events.remove(event)
                    return event
            self.sock.settimeout(max(1.0, deadline - time.time()))
            try:
                reply = self._read()
            except socket.timeout:
                break
            finally:
                self.sock.settimeout(None)
            if "event" in reply:
                self.events.append(reply)
        raise QMPError(f"no {name} from QEMU within {int(timeout)}s")


def backup(qmp: QMP, device: str, target: str) -> None:
    """Copy the disk as it is now (with the VM paused, the moment of the memory dump)."""
    qmp.run("drive-backup", {"job-id": "capture", "device": device, "sync": "full",
                             "target": target, "format": "qcow2"})
    event = qmp.wait_event("BLOCK_JOB_COMPLETED", 6 * 3600)
    if event["data"].get("error"):
        raise QMPError(f"disk copy failed: {event['data']['error']}")


def elf2raw(src: str, dst: str) -> int:
    """Write each PT_LOAD segment of an ELF64 core at its physical address. Returns bytes written."""
    written = 0
    with open(src, "rb") as elf, open(dst, "wb") as raw:
        header = elf.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
            raise ValueError(f"{src} isn't a little-endian ELF64 core")
        phoff, = struct.unpack_from("<Q", header, 32)
        phentsize, phnum = struct.unpack_from("<HH", header, 54)
        segments = []
        for i in range(phnum):
            elf.seek(phoff + i * phentsize)
            p_type, _, p_offset, _, p_paddr, p_filesz = struct.unpack("<IIQQQQ", elf.read(40))
            if p_type == 1 and p_filesz:  # PT_LOAD
                segments.append((p_paddr, p_offset, p_filesz))
        end = 0
        for paddr, offset, size in sorted(segments):
            elf.seek(offset)
            raw.seek(paddr)
            left = size
            while left:
                block = elf.read(min(left, 64 << 20))
                if not block:
                    raise ValueError(f"{src} ends inside a segment")
                raw.write(block)
                left -= len(block)
            written += size
            end = max(end, paddr + size)
        raw.truncate(end)
    return written


def main(argv) -> int:
    if len(argv) == 4 and argv[1] == "elf2raw":
        print(elf2raw(argv[2], argv[3]))
        return 0
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        qmp = QMP(argv[1])
        if argv[2] == "keys":
            pause = float(argv[5]) if len(argv) > 5 else 1.0
            for _ in range(int(argv[4])):
                qmp.run("send-key", {"keys": [{"type": "qcode", "data": argv[3]}]})
                time.sleep(pause)
        elif argv[2] == "backup":
            backup(qmp, argv[3], argv[4])
        else:
            print(json.dumps(qmp.run(argv[2], json.loads(argv[3]) if len(argv) > 3 else None)))
    except (OSError, QMPError) as exc:
        print(f"qmp: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
