"""Smith's language model: where free-text answers come from, and the check that keeps it on the network.

Two kinds of endpoint, both run by the analyst's own organisation:
    ollama   Ollama's own API (/api/tags, /api/generate), on this machine or another
    openai   the OpenAI-compatible API (/v1/models, /v1/chat/completions) that LM Studio, vLLM,
             llama.cpp's server, LocalAI and Ollama itself serve, with an optional API key

The machine Rowanholt runs on may not be able to run a model, so the model can be on another one: a
GPU box on the LAN, or across the tailnet. It can't be a cloud service. Every request first resolves
the endpoint's host, and every address it resolves to must be loopback, RFC 1918, Tailscale's
100.64.0.0/10 (CGNAT), link-local or IPv6 unique-local; anything else is refused before a byte of the
case is sent (ROWANHOLT_ALLOW_PUBLIC_MODEL=1 lifts that, for an admin who knowingly wants it).
Redirects aren't followed. The check runs per request, not only when the setting is saved, so a name
that later resolves elsewhere is caught then.

An admin sets it on Steward's Smith page; until then it is the environment's: OLLAMA_HOST (default
http://host.docker.internal:11434, the host's Ollama) and ROWANHOLT_MODEL_NAME. The setting, with any
API key, lives in smith-model.json beside users.json (or the path in ROWANHOLT_SMITH_MODEL), readable
by the backend's user only; the API shows the key only as whether there is one.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

PROVIDERS = ("ollama", "openai")
DEFAULT_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
DEFAULT_MODEL = os.getenv("ROWANHOLT_MODEL_NAME", "llama3.2:3b")
# Ollama's own default window (2048 tokens) is shorter than the case context Smith sends
NUM_CTX = int(os.getenv("ROWANHOLT_NUM_CTX", "8192"))
# 0.0.0.0/8 ("this network") is never routed: OrbStack's host.docker.internal is 0.250.250.254
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]
_lock = threading.Lock()


class ModelRefused(Exception):
    """The endpoint isn't one Smith may send a case to, or the setting is incomplete."""


def store_path() -> Path:
    explicit = os.environ.get("ROWANHOLT_SMITH_MODEL")
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("USERS_FILE", "/app/data/users.json")).parent / "smith-model.json"


def defaults() -> Dict[str, Any]:
    return {"provider": "ollama", "url": DEFAULT_HOST, "model": DEFAULT_MODEL, "api_key": ""}


def load() -> Dict[str, Any]:
    """The saved setting, else the environment's."""
    try:
        saved = json.loads(store_path().read_text())
        if isinstance(saved, dict) and saved.get("provider") in PROVIDERS and saved.get("url"):
            return {**defaults(), **saved}
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        logger.error("Ignoring Smith's model setting at %s: %s", store_path(), exc)
    return defaults()


def save(setting: Dict[str, Any]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = path.with_name(path.name + ".tmp")
        # the API key may be in it: readable by the backend's user only, like users.json
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(setting, fh, indent=2)
        os.replace(tmp, path)


def reset() -> None:
    """Back to the environment's setting."""
    with _lock:
        try:
            store_path().unlink()
        except FileNotFoundError:
            pass


def public(setting: Dict[str, Any]) -> Dict[str, Any]:
    """The setting as the API shows it: the key only as whether there is one."""
    shown = {k: v for k, v in setting.items() if k != "api_key"}
    shown["has_api_key"] = bool(setting.get("api_key"))
    shown["saved"] = store_path().exists()
    return shown


def setting_problem(provider: str, url: str, model: str) -> Optional[str]:
    """Why a setting can't be saved as it stands, or None (the network check is separate)."""
    if provider not in PROVIDERS:
        return f"The kind of endpoint must be one of {', '.join(PROVIDERS)}."
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "The URL must be http:// or https:// and name a host, such as http://192.168.1.20:11434."
    if parts.username or parts.password:
        return "Put the API key in its own field, not in the URL."
    if parts.query or parts.fragment:
        return "The URL is the server's address only, with no ? or # part."
    if not (model or "").strip():
        return "Name the model to use."
    return None


def public_allowed() -> bool:
    return os.environ.get("ROWANHOLT_ALLOW_PUBLIC_MODEL", "").lower() in ("1", "true", "yes")


def is_private(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in PRIVATE_NETS)


def resolve(host: str) -> List[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


async def check_network(url: str) -> None:
    """Raises ModelRefused unless every address the URL's host resolves to is a private one."""
    host = urlsplit(url).hostname or ""
    try:
        addresses = await asyncio.get_running_loop().run_in_executor(None, resolve, host)
    except (socket.gaierror, UnicodeError) as exc:
        raise ModelRefused(f"{host} doesn't resolve from Rowanholt's backend: {exc}") from exc
    if public_allowed():
        return
    public = [a for a in addresses if not is_private(a)]
    if public:
        raise ModelRefused(
            f"{host} resolves to {', '.join(public)}, which isn't a private address. Smith only sends "
            "a case to a model on this machine, the local network or the tailnet (loopback, 10/8, "
            "172.16/12, 192.168/16, 100.64/10). Set ROWANHOLT_ALLOW_PUBLIC_MODEL=1 in .env to allow "
            "it anyway.")


def _installed(model: str, models: List[str]) -> bool:
    return model in models or any(model in m for m in models)


def old_model_names(model: str) -> List[str]:
    """What a smith model (src/models/Modelfile.smith*) was called before the analyst was renamed,
    newest first: smith-qwen was aule-qwen (Aulë, until 12 November 2026) and before that eru-qwen
    (Eru, until 9 November 2026); smith:latest was aule:latest and eru:latest. Empty for any other model."""
    if model == "smith" or model.startswith(("smith-", "smith:")):
        return [old + model[len("smith"):] for old in ("aule", "eru")]
    return []


class ModelClient:
    """Smith's model, as the saved setting (or the environment) has it, read afresh on each call."""

    def __init__(self, setting: Optional[Dict[str, Any]] = None):
        self.fixed = setting  # tests and Steward's Test button; None: load() each time
        # The model asked for; model is the one used, an old name when only that is pulled
        self.model = (setting or load())["model"]

    @property
    def setting(self) -> Dict[str, Any]:
        return self.fixed or load()

    @property
    def host(self) -> str:
        return self.setting["url"].rstrip("/")

    def _headers(self, setting: Dict[str, Any]) -> Dict[str, str]:
        key = setting.get("api_key")
        return {"Authorization": f"Bearer {key}"} if key else {}

    def choose_model(self, models: List[str]) -> str:
        """The configured model, or an old name of it when only that is pulled (old_model_names)."""
        configured = self.setting["model"]
        if _installed(configured, models):
            return configured
        for old in old_model_names(configured):
            if _installed(old, models):
                if self.model != old:
                    logger.info(f"{configured} isn't pulled but {old}, its name before Smith, is: using {old}")
                return old
        return configured

    async def check_available(self) -> Dict[str, Any]:
        """Whether the endpoint answers, the models it has and whether the configured one is among them."""
        import httpx

        setting = self.setting
        base = setting["url"].rstrip("/")
        try:
            await check_network(base)
        except ModelRefused as exc:
            return {"available": False, "refused": True, "error": str(exc)}
        path = "/api/tags" if setting["provider"] == "ollama" else "/v1/models"
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                response = await client.get(f"{base}{path}", headers=self._headers(setting))
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.debug(f"Smith's model endpoint not available: {exc}")
            return {"available": False, "error": str(exc)}
        if setting["provider"] == "ollama":
            models = [m.get("name") for m in data.get("models", []) if m.get("name")]
        else:
            models = [m.get("id") for m in data.get("data", []) if m.get("id")]
        self.model = self.choose_model(models)
        return {"available": True, "models": models, "default_model": self.model,
                "model_loaded": _installed(self.model, models)}

    async def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """The model's answer to prompt; raises ModelRefused, or httpx's errors when it doesn't answer."""
        import httpx

        setting = self.setting
        base = setting["url"].rstrip("/")
        await check_network(base)
        if self.model not in (setting["model"], *old_model_names(setting["model"])):
            self.model = setting["model"]  # the setting changed since the last check
        if setting["provider"] == "ollama":
            url = f"{base}/api/generate"
            payload: Dict[str, Any] = {"model": self.model, "prompt": prompt, "stream": False,
                                       "options": {"num_ctx": NUM_CTX}}
            if system:
                payload["system"] = system
        else:
            url = f"{base}/v1/chat/completions"
            messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
            payload = {"model": self.model, "messages": messages, "stream": False}
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=self._headers(setting))
            response.raise_for_status()
            data = response.json()
        if setting["provider"] == "ollama":
            return data.get("response", "")
        choices = data.get("choices") or [{}]
        return (choices[0].get("message") or {}).get("content", "") or ""
