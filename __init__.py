"""hermes-hackathon-plugin — starter scaffold.

This is a placeholder. Replace the register() body with the real plugin
implementation once the concept is decided. Keep the `ping` tool or remove it
and update `provides_tools` in plugin.yaml to match.
"""

from __future__ import annotations

import logging

from .schemas import PING_SCHEMA
from .tools import ping_handler

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    ctx.register_tool(name="ping", toolset="hackathon", schema=PING_SCHEMA, handler=ping_handler)
    logger.info("hermes-hackathon-plugin loaded")
