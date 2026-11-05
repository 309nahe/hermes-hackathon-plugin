"""Tool handler implementations for hermes-hackathon-plugin."""

from __future__ import annotations

import json


def ping_handler(args: dict, **kwargs) -> str:
    name = (args or {}).get("name", "world")
    return json.dumps({"pong": f"hello, {name}"})


__all__ = ["ping_handler"]
