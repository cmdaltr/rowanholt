"""Online lookups (src/web/backend/threat_intel_lookup.py): off by default, only IPs, domains and
hashes that may leave, any analyst but never Smith, cached, and VirusTotal's answers read right.
Nothing is sent anywhere: the fetcher is swapped for one that records what it was asked.

Run from tests/unit: python3 -m unittest test_threat_intel_lookup.py
"""

import io
import unittest
import urllib.error
from unittest import mock

from test_server_access import BackendCase, TestClient

SHA256 = "a" * 64
VT_BODY = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20},
    "reputation": -12, "last_analysis_date": 1762214400, "tags": ["trojan"]}}}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipIf(TestClient is None, "backend requirements (fastapi) not installed")
class OnlineLookupTest(BackendCase):
    def setUp(self):
        import threat_intel_lookup as online
        self.online = online
        online.clear_cache()
        self.asked = []
        self.answer = VT_BODY

        def fake(url, headers):
            self.asked.append((url, headers))
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        patches = [mock.patch.object(online, "fetch", fake),
                   mock.patch.object(self.settings, "rowanholt_online_lookups", "virustotal"),
                   mock.patch.object(self.settings, "virustotal_api_key", "test-key")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def look(self, value, headers=None):
        return self.client.post("/api/threat-intel/lookup", headers=headers or self.alice, json={"value": value})

    def test_off_unless_provider_and_key(self):
        with mock.patch.object(self.settings, "virustotal_api_key", ""):
            self.assertEqual(self.client.get("/api/threat-intel/lookup", headers=self.alice).json(),
                             {"enabled": False, "provider": None})
            self.assertEqual(self.look("8.8.8.8").status_code, 404)
        for setting in ("", "dns"):  # Elrond's DNS lookups alone don't turn VirusTotal on
            with mock.patch.object(self.settings, "rowanholt_online_lookups", setting):
                self.assertEqual(self.look("8.8.8.8").status_code, 404)
        with mock.patch.object(self.settings, "rowanholt_online_lookups", "dns, VirusTotal"):
            self.assertEqual(self.client.get("/api/threat-intel/lookup", headers=self.alice).json()["provider"],
                             "virustotal")
        self.assertEqual(self.asked, [])
        self.assertEqual(self.client.get("/api/threat-intel/lookup", headers=self.alice).json(),
                         {"enabled": True, "provider": "virustotal"})

    def test_an_analyst_looks_up_a_hash(self):
        resp = self.look(SHA256.upper())
        self.assertEqual(resp.status_code, 200, resp.text)  # not admin-only, unlike the other POSTs
        body = resp.json()
        self.assertEqual((body["kind"], body["value"], body["malicious"], body["harmless"]), ("hash", SHA256, 7, 60))
        self.assertEqual(body["last_analysis"], "2025-11-04T00:00:00Z")
        self.assertEqual(body["link"], f"https://www.virustotal.com/gui/file/{SHA256}")
        url, headers = self.asked[0]
        self.assertEqual(url, f"https://www.virustotal.com/api/v3/files/{SHA256}")
        self.assertEqual(headers["x-apikey"], "test-key")

    def test_cached_for_the_hour(self):
        self.look("evil.example.com")
        again = self.look("Evil.Example.COM.").json()
        self.assertTrue(again["cached"])
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(self.asked[0][0], "https://www.virustotal.com/api/v3/domains/evil.example.com")

    def test_what_never_leaves(self):
        for value in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fe80::1", "::1", "100.64.0.1",
                      "dc01.corp", "fileserver.local", "ws-01", "powershell.exe -enc AAAA", "C:\\Temp\\x.exe",
                      "wpad.home.arpa", "abc"):
            self.assertEqual(self.look(value).status_code, 400, value)
        self.assertEqual(self.asked, [])
        self.assertEqual(self.look("[198.51.100.7]").status_code, 400)  # documentation range: not global
        self.assertEqual(self.look("[8.8.8.8]").json()["value"], "8.8.8.8")

    def test_never_for_smith(self):
        made = self.client.post("/api/auth/tokens", headers=self.alice,
                                json={"name": "smith", "scope": "smith-mcp", "days": 30}).json()
        self.assertEqual(self.look("8.8.8.8", bearer(made["token"])).status_code, 403)
        self.assertEqual(self.look("8.8.8.8", {**self.alice, "X-Rowanholt-Agent": "smith-mcp"}).status_code, 403)
        self.assertEqual(self.asked, [])
        full = self.client.post("/api/auth/tokens", headers=self.alice,
                                json={"name": "script", "scope": "full", "days": 30}).json()
        self.assertEqual(self.look("8.8.8.8", bearer(full["token"])).status_code, 200)

    def test_signed_in_only(self):
        self.assertEqual(self.client.post("/api/threat-intel/lookup", json={"value": "8.8.8.8"}).status_code, 401)

    def test_provider_answers(self):
        def http_error(code):
            return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))
        self.answer = http_error(404)
        body = self.look("1.1.1.1").json()
        self.assertEqual((body["found"], body["link"]), (False, "https://www.virustotal.com/gui/ip-address/1.1.1.1"))
        self.answer = http_error(429)
        self.assertEqual(self.look("1.0.0.1").status_code, 429)
        self.answer = http_error(401)
        self.assertEqual(self.look("9.9.9.9").status_code, 502)
        self.answer = urllib.error.URLError("timed out")
        self.assertEqual(self.look("149.112.112.112").status_code, 502)
