"""Client for a typed-decision model (OpenRouter ``/api/alpha/decisions``, default model Perplexity pplx-decider).

The model never runs the workflow. The agent sends a small, redacted ``state`` and a few typed questions and gets back
probabilities:

* ``noul``   -> {"noul": p}                      p = probability of "true" (0..1)
* ``choice`` -> {"choice": key, "probabilities": {key: p}}
* ``score``  -> {"score": x, ...}

Configuration (environment or ``.env``):
  OPENROUTER_API_KEY   required to enable the decider; without it every decision falls back to the agent's rules
  SCG_DECIDER_MODEL    optional, default ``perplexity/pplx-decider-flash-v1.3:free``
  SCG_DECIDER_URL      optional, default ``https://openrouter.ai/api/alpha/decisions``

Any transport/format error returns ``None``; the caller then uses its rule. Secrets are redacted and text is truncated before sending.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

import requests

from llm.client import redact

DEFAULT_MODEL = "perplexity/pplx-decider-flash-v1.3:free"
DEFAULT_URL = "https://openrouter.ai/api/alpha/decisions"
MAX_STATE_CHARS = 6000


def _clip(x: Any) -> Any:
    if isinstance(x, str):
        x = redact(x)
        return x if len(x) <= MAX_STATE_CHARS else x[:MAX_STATE_CHARS] + " ...[truncated]"
    return x


class Decider:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, url: Optional[str] = None, timeout: int = 45):
        self.api_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY") or None
        self.model = model or os.environ.get("SCG_DECIDER_MODEL") or DEFAULT_MODEL
        self.url = url or os.environ.get("SCG_DECIDER_URL") or DEFAULT_URL
        self.timeout = timeout
        self.calls: list[dict[str, Any]] = []  # metadata only (no state text), kept for the report

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def ask(self, state: list[Any], questions: dict[str, dict]) -> Optional[dict[str, dict]]:
        if not self.enabled:
            return None
        body = {"model": self.model, "state": [_clip(s) for s in state], "questions": questions}
        t0 = time.time()
        meta: dict[str, Any] = {"model": self.model, "questions": list(questions), "ok": False}
        try:
            r = requests.post(self.url, headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                              data=json.dumps(body), timeout=self.timeout)
            meta["http_status"] = r.status_code
            if r.status_code != 200:
                meta["error"] = redact(r.text[:200])
                return None
            answers = r.json().get("answers")
            if not isinstance(answers, dict):
                meta["error"] = "response has no 'answers' object"
                return None
            meta["ok"] = True
            return answers
        except (requests.RequestException, ValueError) as e:
            meta["error"] = f"{type(e).__name__}: {redact(str(e))[:200]}"
            return None
        finally:
            meta["seconds"] = round(time.time() - t0, 2)
            self.calls.append(meta)
