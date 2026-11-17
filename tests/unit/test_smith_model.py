"""Smith's model endpoint (src/web/backend/smith_model.py): the private-address check, both providers,
and the admin routes that set it.

Run: python3 -m unittest tests/unit/test_smith_model.py
"""

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import test_server_access  # noqa: F401,E402  (sets the backend's environment before anything imports it)
from test_server_access import BackendCase, TestClient  # noqa: E402

try:
    import httpx
    import smith_model
except ImportError:  # backend requirements not installed
    httpx = smith_model = None


def run(coro):
    return asyncio.run(coro)


def resolving(*addresses, module=None):
    return mock.patch.object(module or smith_model, "resolve", return_value=list(addresses))


def answering(handler):
    """httpx.AsyncClient with every request answered by handler."""
    real = httpx.AsyncClient
    return mock.patch.object(httpx, "AsyncClient",
                             lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


@unittest.skipIf(smith_model is None, "backend requirements (httpx) not installed")
class AddressTest(unittest.TestCase):
    def test_private_addresses(self):
        for address in ("127.0.0.1", "10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.20", "100.101.102.103",
                        "169.254.1.1", "::1", "fd7a:115c:a1e0::1", "fe80::1%en0", "::ffff:192.168.1.5"):
            self.assertTrue(smith_model.is_private(address), address)
        for address in ("8.8.8.8", "172.32.0.1", "100.128.0.1", "104.18.0.1", "2606:4700::1", "::ffff:8.8.8.8"):
            self.assertFalse(smith_model.is_private(address), address)

    def test_a_public_endpoint_is_refused(self):
        with resolving("192.168.1.20", "104.18.32.7"):
            with self.assertRaises(smith_model.ModelRefused) as refused:
                run(smith_model.check_network("http://gpu.example.org:1234"))
        self.assertIn("104.18.32.7", str(refused.exception))
        with resolving("100.88.1.4"):
            run(smith_model.check_network("http://gpu.tail180683.ts.net:11434"))  # the tailnet

    def test_the_override(self):
        with resolving("104.18.32.7"), mock.patch.dict(os.environ, {"ROWANHOLT_ALLOW_PUBLIC_MODEL": "1"}):
            run(smith_model.check_network("https://api.example.org"))

    def test_setting_problems(self):
        self.assertIsNone(smith_model.setting_problem("openai", "http://192.168.1.20:1234", "qwen3-8b"))
        self.assertIn("one of", smith_model.setting_problem("anthropic", "http://h", "m"))
        self.assertIn("http://", smith_model.setting_problem("ollama", "ftp://h", "m"))
        self.assertIn("API key", smith_model.setting_problem("openai", "http://user:key@h:1234", "m"))
        self.assertIn("? or #", smith_model.setting_problem("openai", "http://h:1234/?x=1", "m"))
        self.assertIn("model", smith_model.setting_problem("ollama", "http://h:11434", " "))


@unittest.skipIf(smith_model is None, "backend requirements (httpx) not installed")
class ProviderTest(unittest.TestCase):
    def test_openai_compatible(self):
        seen = []

        def handler(request):
            seen.append(request)
            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen3-8b"}, {"id": "gemma-3"}]})
            return httpx.Response(200, json={"choices": [{"message": {"content": "T1059.001"}}]})

        client = smith_model.ModelClient({"provider": "openai", "url": "http://10.0.0.5:1234/", "model": "qwen3-8b",
                                          "api_key": "sk-local"})
        with resolving("10.0.0.5"), answering(handler):
            status = run(client.check_available())
            answer = run(client.generate("Which technique?", system="You are Smith."))
        self.assertEqual(status["models"], ["qwen3-8b", "gemma-3"])
        self.assertTrue(status["model_loaded"])
        self.assertEqual(answer, "T1059.001")
        chat = seen[-1]
        self.assertEqual(chat.url.path, "/v1/chat/completions")
        self.assertEqual(chat.headers["Authorization"], "Bearer sk-local")
        body = httpx.Response(200, content=chat.content).json()
        self.assertEqual([m["role"] for m in body["messages"]], ["system", "user"])

    def test_ollama(self):
        def handler(request):
            if request.url.path == "/api/tags":
                return httpx.Response(200, json={"models": [{"name": "llama3.2:3b"}]})
            self.assertNotIn("Authorization", request.headers)
            return httpx.Response(200, json={"response": "an answer"})

        client = smith_model.ModelClient({"provider": "ollama", "url": "http://192.168.1.20:11434", "model": "llama3.2:3b",
                                          "api_key": ""})
        with resolving("192.168.1.20"), answering(handler):
            self.assertTrue(run(client.check_available())["model_loaded"])
            self.assertEqual(run(client.generate("hello")), "an answer")

    def test_nothing_is_sent_to_a_public_address(self):
        handler = mock.Mock(side_effect=AssertionError("sent"))
        client = smith_model.ModelClient({"provider": "openai", "url": "http://llm.example.org", "model": "m"})
        with resolving("104.18.32.7"), answering(handler):
            self.assertTrue(run(client.check_available())["refused"])
            with self.assertRaises(smith_model.ModelRefused):
                run(client.generate("the case"))
        handler.assert_not_called()


@unittest.skipIf(TestClient is None or smith_model is None, "backend requirements (fastapi) not installed")
class RoutesTest(BackendCase):
    """The routes' own smith_model: the backend imports it as ai_routes does, not as this file does."""

    def setUp(self):
        self.model = sys.modules["ai_routes"].smith_model

    def tearDown(self):
        self.model.reset()

    def test_admins_only(self):
        alice = self.alice
        self.assertEqual(self.client.get("/api/ai/model", headers=alice).status_code, 403)
        self.assertEqual(self.client.put("/api/ai/model", headers=alice, json={
            "provider": "ollama", "url": "http://10.0.0.5:11434", "model": "m"}).status_code, 403)

    def test_saved_with_the_key_kept_back(self):
        body = {"provider": "openai", "url": "http://10.0.0.5:1234", "model": "qwen3-8b", "api_key": "sk-local"}
        with resolving("10.0.0.5", module=self.model):
            saved = self.client.put("/api/ai/model", headers=self.admin, json=body)
        self.assertEqual(saved.status_code, 200, saved.text)
        shown = self.client.get("/api/ai/model", headers=self.admin).json()
        self.assertEqual((shown["provider"], shown["url"], shown["model"]), ("openai", "http://10.0.0.5:1234", "qwen3-8b"))
        self.assertTrue(shown["has_api_key"] and shown["saved"])
        self.assertNotIn("sk-local", saved.text + str(shown))
        self.assertEqual(self.model.load()["api_key"], "sk-local")
        self.assertEqual(oct(self.model.store_path().stat().st_mode & 0o777), "0o600")
        # Saved again without a key: the key stays; with "": it goes
        with resolving("10.0.0.5", module=self.model):
            self.client.put("/api/ai/model", headers=self.admin, json={**body, "api_key": None})
            self.assertEqual(self.model.load()["api_key"], "sk-local")
            self.client.put("/api/ai/model", headers=self.admin, json={**body, "api_key": ""})
            self.assertEqual(self.model.load()["api_key"], "")
        reset = self.client.delete("/api/ai/model", headers=self.admin).json()
        self.assertEqual(reset["provider"], "ollama")
        self.assertFalse(reset["saved"])

    def test_a_public_endpoint_isnt_saved(self):
        with resolving("104.18.32.7", module=self.model):
            refused = self.client.put("/api/ai/model", headers=self.admin, json={
                "provider": "openai", "url": "https://llm.example.org", "model": "m"})
        self.assertEqual(refused.status_code, 403)
        self.assertIn("isn't a private address", refused.json()["detail"])
        self.assertFalse(self.model.store_path().exists())


if __name__ == "__main__":
    unittest.main()
