"""Unit tests for the lab VM consoles (FR-04): finding each VM's VNC port (src/mordor/lab/consoles.py),
the lab agent's tunnel to it (lab/agent/lab_agent.py), and the backend's websocket relay for
signed-in admins only (src/web/backend/lab_routes.py).

No VM is involved: a stand-in VNC server on 127.0.0.1 says hello and echoes, and the real lab agent's
handler runs on a loopback port with its VM lookup patched to point at it.
"""

import plistlib
import socket
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "lab" / "agent"))

from src.mordor.lab import consoles, engines  # noqa: E402

from test_server_access import TMP, BackendCase, TestClient  # noqa: E402

BANNER = b"RFB 003.008\n"


class StandInVNC:
    """A TCP server on loopback that sends an RFB banner, then echoes; counts its connections."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn: socket.socket) -> None:
        with conn:
            conn.sendall(BANNER)
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                conn.sendall(data)

    def close(self) -> None:
        self.sock.close()


class StandInAgent:
    """The real lab agent's handler on a loopback port, with one VM (tart/vm1) whose console is
    the stand-in VNC server. Records every tunnel it was asked for and where it connected."""

    def __init__(self, vnc_port: int, token: str = "agent-token") -> None:
        import lab_agent

        self.module = lab_agent
        self.asked = []
        self.connected = []
        real_connect = socket.create_connection

        def find(engine, name, found=None):
            self.asked.append((engine, name))
            if (engine, name) == ("tart", "vm1"):
                return {"engine": "tart", "name": "vm1", "port": vnc_port, "password": "pw", "auth": "password"}
            return None

        def connect(address, *args, **kwargs):
            self.connected.append(address)
            return real_connect(address, *args, **kwargs)

        self.patches = [
            mock.patch.object(lab_agent.consoles, "find", find),
            mock.patch.object(lab_agent.consoles, "discover_live", lambda: [find("tart", "vm1")]),
            mock.patch.object(lab_agent.mordor_api, "configure", lambda state: None),
            mock.patch.object(lab_agent.socket, "create_connection", connect),
        ]
        for p in self.patches:
            p.start()
        lab_agent.Handler.token = token
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), lab_agent.Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        for p in self.patches:
            p.stop()


def raw_request(port: int, path: str, headers: dict) -> socket.socket:
    sock = socket.socket()  # not create_connection, which the stand-in agent records
    sock.settimeout(5)
    sock.connect(("127.0.0.1", port))
    lines = [f"GET {path} HTTP/1.1", "Host: 127.0.0.1"] + [f"{k}: {v}" for k, v in headers.items()]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    return sock


def read_head(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def read_exactly(sock: socket.socket, want: bytes, already: bytes = b"") -> bytes:
    data = already
    while len(data) < len(want):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class ConsoleDiscoveryTest(unittest.TestCase):
    def test_tart_log_gives_loopback_port_and_password(self):
        log = "Starting\nVNC server is running at vnc://:pa%2Fss@127.0.0.1:61234\n"
        self.assertEqual(consoles.parse_tart_log(log), {"port": 61234, "password": "pa/ss"})
        # The window variant, and the last run's address wins
        log += "Opening vnc://:second@127.0.0.1:61300...\n"
        self.assertEqual(consoles.parse_tart_log(log), {"port": 61300, "password": "second"})

    def test_tart_log_refuses_anything_off_loopback(self):
        for text in ("", "no url here", "VNC server is running at vnc://:pw@192.168.64.1:5900",
                     "vnc://:pw@example.org:5900", "vnc://:pw@127.0.0.1", "vnc://:pw@127.0.0.1:notaport"):
            self.assertIsNone(consoles.parse_tart_log(text), text)

    def test_qemu_vnc_on_loopback_only(self):
        self.assertEqual(consoles.parse_qemu_vnc(["-vnc", "127.0.0.1:59"]), 5959)
        self.assertEqual(consoles.parse_qemu_vnc(["-cpu", "host", "-vnc localhost:3"]), 5903)
        self.assertEqual(consoles.parse_qemu_vnc(["-vnc", "127.0.0.1:61,share=allow-exclusive"]), 5961)
        for args in ([], ["-vnc", ":59"], ["-vnc", "0.0.0.0:59"], ["-vnc", "unix:/tmp/vnc"],
                     ["-vnc", "127.0.0.1:59,password=on"], ["-vnc", "127.0.0.1:59,reverse=on"],
                     ["-vnc", "127.0.0.1:x"], ["-vnc"], ["-vnc", "127.0.0.1:70000"]):
            self.assertIsNone(consoles.parse_qemu_vnc(args), args)

    def test_set_qemu_vnc_replaces_any_earlier_one(self):
        args = ["-cpu", "host", "-vnc", "127.0.0.1:59", "-vnc :3"]
        self.assertEqual(consoles.set_qemu_vnc(args, 71), ["-cpu", "host", "-vnc", "127.0.0.1:71"])
        self.assertEqual(consoles.set_qemu_vnc(args, None), ["-cpu", "host"])

    def test_utm_registry(self):
        prefs = plistlib.dumps({"Registry": {
            "f3ee9e76-8884-4d42-ad25-ea7158a75f16": {"Name": "old-name", "Package": {"Path": "/vms/win.utm"}},
            "BROKEN": {"Package": "nope"}}, "HideDockIcon": True})
        self.assertEqual(consoles.parse_utm_registry(prefs), {"F3EE9E76-8884-4D42-AD25-EA7158A75F16": "/vms/win.utm"})
        self.assertEqual(consoles.parse_utm_registry(b"not a plist"), {})

    def test_discover_running_vms_only_and_drops_a_shared_port(self):
        tart = [{"name": "mac1", "state": "running"}, {"name": "mac2", "state": "stopped"},
                {"name": "lin1", "state": "running"}]
        utm = [{"name": "win", "uuid": "U1", "state": "running"}, {"name": "win-2", "uuid": "U2", "state": "running"},
               {"name": "win-3", "uuid": "U3", "state": "running"}, {"name": "off", "uuid": "U4", "state": "stopped"}]
        logs = {"mac1": "VNC server is running at vnc://:abc@127.0.0.1:60001", "lin1": "",
                "mac2": "VNC server is running at vnc://:old@127.0.0.1:60002"}
        configs = {"/a.utm": {"QEMU": {"AdditionalArguments": ["-vnc", "127.0.0.1:59"]}},
                   "/b.utm": {"QEMU": {"AdditionalArguments": ["-vnc", "127.0.0.1:59"]}},  # a clone, same port
                   "/c.utm": {"QEMU": {"AdditionalArguments": ["-vnc", "127.0.0.1:70"]}},
                   "/d.utm": {"QEMU": {"AdditionalArguments": ["-vnc", "127.0.0.1:71"]}}}
        registry = {"U1": "/a.utm", "U2": "/b.utm", "U3": "/c.utm", "U4": "/d.utm"}
        with self.assertLogs(consoles.log, "WARNING"):
            found = consoles.discover(tart, utm, registry, read_log=logs.__getitem__, read_config=configs.__getitem__)
        self.assertEqual(found, [
            {"engine": "tart", "name": "mac1", "port": 60001, "password": "abc", "auth": "password"},
            {"engine": "utm", "name": "win-3", "port": 5970, "password": "", "auth": "none"}])
        self.assertEqual(consoles.find("utm", "win-3", found)["port"], 5970)
        self.assertIsNone(consoles.find("utm", "win", found))

    def test_free_display_for_a_clone(self):
        self.assertEqual(consoles.free_display([59, 60]), 70)
        self.assertEqual(consoles.free_display([70, 71, 73]), 72)
        self.assertIsNone(consoles.free_display(range(70, 100)))

    def test_utm_clone_gets_its_own_console_port(self):
        calls, renumbered = [], []
        listing = "UUID Status Name\nA-1 stopped win\nB-2 stopped win-2\n"
        with mock.patch.object(engines, "run", lambda argv, **k: calls.append(list(argv)) or listing), \
                mock.patch.object(engines, "utm_up", lambda: None), \
                mock.patch.object(consoles, "renumber_utm_clone", lambda n, u: renumbered.append((n, u))):
            engines.UTM().clone("win", "win-2")
        self.assertIn(["utmctl", "clone", "--hide", "win", "--name", "win-2"], calls)
        self.assertEqual(renumbered, [("win-2", "B-2")])

    def test_renumber_rewrites_the_clone_config(self):
        root = Path(TMP) / "utm-renumber"
        for name, display in (("src", 70), ("clone", 70), ("other", 71)):
            (root / f"{name}.utm").mkdir(parents=True, exist_ok=True)
            with open(root / f"{name}.utm" / "config.plist", "wb") as fh:
                plistlib.dump({"QEMU": {"AdditionalArguments": ["-cpu", "host", "-vnc", f"127.0.0.1:{display}"]}}, fh)
        registry = {n.upper(): str(root / f"{n}.utm") for n in ("src", "clone", "other")}
        ran = []
        with mock.patch.object(consoles, "read_utm_registry", lambda: registry), \
                mock.patch.object(consoles, "run", lambda argv, **k: ran.append(argv) or ""):
            self.assertEqual(consoles.renumber_utm_clone("clone", "clone"), 5972)
        with open(root / "clone.utm" / "config.plist", "rb") as fh:
            self.assertEqual(plistlib.load(fh)["QEMU"]["AdditionalArguments"], ["-cpu", "host", "-vnc", "127.0.0.1:72"])
        self.assertTrue(any("reload configuration" in " ".join(a) for a in ran))


class AgentTunnelTest(unittest.TestCase):
    def setUp(self):
        self.vnc = StandInVNC()
        self.agent = StandInAgent(self.vnc.port)

    def tearDown(self):
        self.agent.close()
        self.vnc.close()

    def tunnel(self, path, token="agent-token", upgrade="rowanholt-vnc"):
        headers = {"Connection": "Upgrade"}
        if token:
            headers["X-Lab-Token"] = token
        if upgrade:
            headers["Upgrade"] = upgrade
        sock = raw_request(self.agent.port, path, headers)
        head = read_head(sock)
        return sock, head

    def test_tunnel_carries_bytes_both_ways_to_the_vm_port_on_loopback(self):
        sock, head = self.tunnel("/consoles/tart/vm1/connect")
        with sock:
            self.assertTrue(head.split()[1] == b"101", head)
            rest = head.split(b"\r\n\r\n", 1)[1]
            self.assertEqual(read_exactly(sock, BANNER, rest), BANNER)
            sock.sendall(b"hello vm")
            self.assertEqual(read_exactly(sock, b"hello vm"), b"hello vm")
        self.assertEqual(self.agent.connected, [("127.0.0.1", self.vnc.port)])

    def test_refusals_never_connect_anywhere(self):
        cases = [("/consoles/tart/vm1/connect", None, "rowanholt-vnc", b"401"),         # no token
                 ("/consoles/tart/vm1/connect", "wrong", "rowanholt-vnc", b"401"),
                 ("/consoles/docker/vm1/connect", "agent-token", "rowanholt-vnc", b"400"),  # not a VM engine
                 ("/consoles/tart/..%2Fetc/connect", "agent-token", "rowanholt-vnc", b"400"),
                 ("/consoles/tart/vm1/connect", "agent-token", None, b"400"),              # no upgrade asked
                 ("/consoles/tart/vm2/connect", "agent-token", "rowanholt-vnc", b"404"),   # no such console
                 # The query is ignored: the port is always the VM's own
                 ("/consoles/tart/vm2/connect?port=22&host=10.0.0.1", "agent-token", "rowanholt-vnc", b"404")]
        for path, token, upgrade, status in cases:
            sock, head = self.tunnel(path, token=token, upgrade=upgrade)
            sock.close()
            self.assertEqual(head.split()[1], status, path)
        self.assertEqual(self.agent.connected, [])
        self.assertEqual(self.vnc.connections, 0)

    def test_query_cannot_move_the_port(self):
        sock, head = self.tunnel("/consoles/tart/vm1/connect?port=22&host=10.0.0.1")
        sock.close()
        self.assertTrue(head.split()[1] == b"101", head)
        self.assertEqual(self.agent.connected, [("127.0.0.1", self.vnc.port)])

    def test_listing(self):
        sock = raw_request(self.agent.port, "/consoles", {"X-Lab-Token": "agent-token"})
        with sock:
            self.assertIn(b'"port": %d' % self.vnc.port, read_head(sock) + sock.recv(4096))


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class ConsoleRelayTest(BackendCase):
    """The real backend in server mode, relaying to the stand-in agent."""

    def setUp(self):
        import lab_routes

        self.lab_routes = lab_routes
        self.vnc = StandInVNC()
        self.agent = StandInAgent(self.vnc.port)
        token_file = Path(TMP) / "lab-agent-token"
        token_file.write_text("agent-token")
        self.patches = [mock.patch.object(lab_routes, "LAB_AGENT_URL", self.agent.url),
                        mock.patch.object(lab_routes, "LAB_AGENT_TOKEN_PATH", token_file)]
        for p in self.patches:
            p.start()
        self.path = "/api/lab/consoles/tart/vm1/ws"

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.agent.close()
        self.vnc.close()

    def assert_refused(self, path, headers):
        from starlette.websockets import WebSocketDisconnect

        with self.assertRaises(WebSocketDisconnect) as refused:
            with self.client.websocket_connect(path, headers=headers) as ws:
                ws.receive_bytes()
        self.assertEqual(refused.exception.code, 1008, (path, headers))

    def test_admin_gets_the_vm_screen(self):
        with self.client.websocket_connect(self.path, headers=self.admin, subprotocols=["binary"]) as ws:
            self.assertEqual(ws.accepted_subprotocol, "binary")
            self.assertEqual(ws.receive_bytes(), BANNER)
            ws.send_bytes(b"\x03\x00keys")
            self.assertEqual(ws.receive_bytes(), b"\x03\x00keys")
        self.assertEqual(self.agent.asked, [("tart", "vm1")])
        self.assertEqual(self.agent.connected, [("127.0.0.1", self.vnc.port)])

    def test_nobody_else_reaches_the_agent(self):
        origin = {**self.admin, "Origin": "https://evil.example"}
        for headers in ({}, self.alice, self.bob, origin, {"Authorization": "Bearer not-a-token"}):
            self.assert_refused(self.path, headers)
        # Not a VM name, or not a VM engine: refused before the agent hears of it
        for path in ("/api/lab/consoles/docker/vm1/ws", "/api/lab/consoles/tart/-vm1/ws",
                     "/api/lab/consoles/tart/vm1%0d%0aX-Evil:%201/ws"):
            self.assert_refused(path, self.admin)
        self.assertEqual(self.agent.asked, [])
        self.assertEqual(self.vnc.connections, 0)

    def test_query_cannot_point_the_relay_elsewhere(self):
        with self.client.websocket_connect(f"{self.path}?host=10.0.0.1&port=22", headers=self.admin) as ws:
            self.assertEqual(ws.receive_bytes(), BANNER)
        self.assertEqual(self.agent.connected, [("127.0.0.1", self.vnc.port)])

    def test_local_mode_still_needs_a_signed_in_admin(self):
        self.settings.rowanholt_server_mode = False
        try:
            self.assert_refused(self.path, {})
            self.assert_refused(self.path, self.alice)
            self.assertEqual(self.agent.asked, [])
            self.assertEqual(self.client.get("/api/lab/consoles").status_code, 401)
            with self.client.websocket_connect(self.path, headers=self.admin) as ws:
                self.assertEqual(ws.receive_bytes(), BANNER)
        finally:
            self.settings.rowanholt_server_mode = True

    def test_default_secret_disables_consoles(self):
        with mock.patch.object(self.settings, "secret_key", self.lab_routes.DEFAULT_SECRET):
            self.assert_refused(self.path, self.admin)
        self.assertEqual(self.agent.asked, [])

    def test_demoted_admin_is_cut_off(self):
        from starlette.websockets import WebSocketDisconnect

        real = self.lab_routes.load_users
        with mock.patch.object(self.lab_routes, "CONSOLE_RECHECK_SECONDS", 0.1):
            with self.client.websocket_connect(self.path, headers=self.admin) as ws:
                self.assertEqual(ws.receive_bytes(), BANNER)
                demoted = {k: {**u, "role": "analyst"} for k, u in real().items()}
                with mock.patch.object(self.lab_routes, "load_users", lambda: demoted):
                    deadline = time.time() + 5
                    with self.assertRaises(WebSocketDisconnect):
                        while time.time() < deadline:
                            ws.receive_bytes()

    def test_agent_refusal_is_explained_to_the_admin(self):
        from starlette.websockets import WebSocketDisconnect

        with self.assertRaises(WebSocketDisconnect) as closed:
            with self.client.websocket_connect("/api/lab/consoles/tart/vm2/ws", headers=self.admin) as ws:
                ws.receive_bytes()
        self.assertEqual(closed.exception.code, 1011)
        self.assertIn("vm2 has no console", closed.exception.reason)
        self.assertEqual(self.vnc.connections, 0)

    def test_console_listing_is_admin_only_and_password_only_in_detail(self):
        self.assertEqual(self.client.get("/api/lab/consoles", headers=self.alice).status_code, 403)
        self.assertEqual(self.client.get("/api/lab/consoles/tart/vm1", headers=self.alice).status_code, 403)
        listing = self.client.get("/api/lab/consoles", headers=self.admin)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json()["consoles"],
                         [{"engine": "tart", "name": "vm1", "port": self.vnc.port, "auth": "password"}])
        detail = self.client.get("/api/lab/consoles/tart/vm1", headers=self.admin).json()
        self.assertEqual(detail["password"], "pw")
        self.assertEqual(self.client.get("/api/lab/consoles/tart/nope", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.get("/api/lab/consoles/docker/vm1", headers=self.admin).status_code, 400)


if __name__ == "__main__":
    unittest.main()
