"""Provider-agnostic LLM client over plain HTTPS (no SDKs). Entirely optional: with no key everything runs deterministically.

Configure in ``.env``:  ``LLM_API_KEY=...``  (Groq ``gsk_``, Gemini ``AIza``, Anthropic ``sk-ant-``, OpenAI ``sk-``).
The provider is detected from the key prefix; override with ``LLM_PROVIDER`` (groq | gemini | anthropic | openai | openai_compatible),
``LLM_MODEL`` and, for compatible endpoints, ``LLM_BASE_URL``. The legacy ``ANTHROPIC_API_KEY`` is still honoured.

Safety: ``redact()`` strips secret-looking tokens from every outgoing prompt, and every call is recorded (size + hash, never content)
in ``CALL_LOG`` so the audit trail can show what left the machine.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

DEFAULT_MODELS = {"groq": "llama-3.3-70b-versatile", "gemini": "gemini-2.0-flash", "anthropic": "claude-sonnet-5-5", "openai": "gpt-4o-mini", "openai_compatible": "default"}
BASE_URLS = {"groq": "https://api.groq.com/openai/v1", "openai": "https://api.openai.com/v1"}
_SECRET = re.compile(r"(gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
                     r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
CALL_LOG: list[dict] = []
_LOCK = threading.Lock()


class LLMError(RuntimeError):
    pass


def detect_provider(key: Optional[str], explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit.lower().replace("-", "_")
    if not key:
        return None
    if key.startswith("gsk_"):
        return "groq"
    if key.startswith("AIza"):
        return "gemini"
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("sk-"):
        return "openai"
    return "openai_compatible"


def redact(text: str) -> str:
    return _SECRET.sub("[REDACTED]", text or "")


@dataclass
class LLM:
    api_key: str
    provider: str
    model: str
    base_url: Optional[str] = None
    timeout: int = 60

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    def complete(self, system: str, user: str, max_tokens: int = 1200, json_mode: bool = False) -> str:
        system, user = redact(system), redact(user)
        t0 = time.time()
        try:
            out = self._call(system, user, max_tokens, json_mode)
            ok = True
        except Exception as e:  # noqa: BLE001
            out, ok = "", False
            err = f"{type(e).__name__}: {str(e)[:160]}"
        with _LOCK:
            CALL_LOG.append({"provider": self.provider, "model": self.model, "prompt_chars": len(system) + len(user), "prompt_sha256": hashlib.sha256((system + user).encode()).hexdigest()[:16],
                             "ok": ok, "seconds": round(time.time() - t0, 2), "response_chars": len(out), **({} if ok else {"error": err})})
        if not ok:
            raise LLMError(err)
        return out

    # ------------------------------------------------------------------ providers
    def _call(self, system: str, user: str, max_tokens: int, json_mode: bool) -> str:
        if self.provider == "anthropic":
            r = requests.post("https://api.anthropic.com/v1/messages", timeout=self.timeout,
                              headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                              json={"model": self.model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]})
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json().get("content", []))
        if self.provider == "gemini":
            body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"maxOutputTokens": max_tokens, **({"responseMimeType": "application/json"} if json_mode else {})}}
            r = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent", timeout=self.timeout,
                              headers={"x-goog-api-key": self.api_key, "content-type": "application/json"}, json=body)
            r.raise_for_status()
            parts = (((r.json().get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
            return "".join(p.get("text", "") for p in parts)
        base = (self.base_url or BASE_URLS.get(self.provider) or "").rstrip("/")
        if not base:
            raise LLMError("LLM_BASE_URL is required for an OpenAI-compatible provider")
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 0.1, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if json_mode and self.provider in ("groq", "openai"):
            body["response_format"] = {"type": "json_object"}
        r = requests.post(f"{base}/chat/completions", timeout=self.timeout, headers={"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"}, json=body)
        r.raise_for_status()
        return ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content", "")


def from_settings(s) -> Optional[LLM]:
    """Build the client from Settings, or None when no key is configured (deterministic mode)."""
    key = getattr(s, "llm_api_key", None)
    if not key:
        return None
    prov = detect_provider(key, getattr(s, "llm_provider", None))
    model = getattr(s, "llm_model", None)
    if not model or (prov != "anthropic" and model.startswith("claude")):  # default model name belongs to another provider
        model = DEFAULT_MODELS.get(prov, "default")
    return LLM(api_key=key, provider=prov, model=model, base_url=getattr(s, "llm_base_url", None))


def extract_json(raw: str) -> dict:
    a, b = raw.find("{"), raw.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("no JSON object in the model reply")
    return json.loads(raw[a:b + 1])
