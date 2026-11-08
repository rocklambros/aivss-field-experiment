#!/usr/bin/env python3
"""
Localhost FinBot with the OpenAI client pointed at a pinned OpenRouter US endpoint.

Version: 1.0.0
Owner: Rock Lambros

Does not edit the lab repo. The key arrives in OPENAI_API_KEY and is never logged.
"""

from __future__ import annotations

import json
import os
import sys

from openai._models import BaseModel

if not hasattr(BaseModel, "dict"):
    BaseModel.dict = BaseModel.model_dump  # type: ignore[attr-defined]

HOST = "127.0.0.1"
PORT = int(os.environ.get("FINBOT_PORT", "5056"))
MODEL = os.environ["FINBOT_MODEL"]
TAG = os.environ["FINBOT_TAG"]
PROVIDER = os.environ["FINBOT_PROVIDER"]
CALL_LOG = os.environ["FINBOT_CALL_LOG"]
calls: list[dict] = []


def served_name(body: dict) -> str:
    served = body.get("provider")
    if isinstance(served, dict):
        served = served.get("name") or served.get("provider_name")
    return str(served or "")


def wrap(client) -> None:
    original = client.chat.completions.create

    def hook(response) -> None:
        if "chat/completions" not in str(response.request.url):
            return
        response.read()
        body = json.loads(response.text)
        served = served_name(body)
        if served.lower() != PROVIDER.lower():
            raise RuntimeError(f"serving provider {served!r} is not the pinned US provider {PROVIDER!r}")
        usage = body.get("usage") or {}
        calls.append({
            "served": served,
            "model": body.get("model"),
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "cost": usage.get("cost"),
        })
        with open(CALL_LOG, "w", encoding="utf-8") as handle:
            json.dump(calls, handle)

    client._client.event_hooks["response"].append(hook)

    def create(*args, **kwargs):
        kwargs["model"] = MODEL
        extra = dict(kwargs.pop("extra_body", None) or {})
        extra["provider"] = {"order": [TAG], "allow_fallbacks": False}
        kwargs["extra_body"] = extra
        return original(*args, **kwargs)

    client.chat.completions.create = create


def patch() -> None:
    import src.services.finbot_agent as agent_mod

    original = agent_mod.FinBotAgent.__init__

    def init(self):
        original(self)
        if self.client is None:
            raise RuntimeError("OpenAI client did not initialize")
        self.model = MODEL
        wrap(self.client)

    agent_mod.FinBotAgent.__init__ = init


def main() -> None:
    sys.path.insert(0, os.getcwd())
    os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"
    patch()
    from src.main import app

    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
