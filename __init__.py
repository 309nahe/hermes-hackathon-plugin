"""RookGuard — track, scan, fix.

Keeps an inventory of the packages installed on the host where the agent runs,
scans it against cve.now, reports prioritized findings with fixed versions,
and applies user-approved upgrades.

Surfaces registered here:
  * tools:    rookguard_inventory, rookguard_scan, rookguard_status, rookguard_fix
  * hooks:    post_tool_call (install tracking), on_session_start + pre_llm_call
              (morning briefing on the first turn)
  * command:  /rookguard inventory|scan|status|fix [package|all]
  * skill:    vuln-triage
"""

from __future__ import annotations

import logging
from pathlib import Path

from . import tools
from .schemas import ROOKGUARD_SCHEMAS

logger = logging.getLogger(__name__)

_SKILL_PATH = Path(__file__).parent / "skills" / "vuln-triage" / "SKILL.md"


def register(ctx) -> None:
    handlers = tools.build_handlers(ctx)

    for schema in ROOKGUARD_SCHEMAS:
        name = schema["name"]
        ctx.register_tool(
            name=name,
            toolset="rookguard",
            schema=schema,
            handler=handlers[name],
        )

    ctx.register_hook("post_tool_call", tools.record_installs)
    ctx.register_hook("on_session_start", tools.on_session_start)
    ctx.register_hook("pre_llm_call", tools.on_pre_llm_call)

    ctx.register_command(
        "rookguard",
        tools.make_command_handler(handlers),
        description="Package inventory, CVE scanning and guided fixes (track, scan, fix).",
        args_hint="inventory|scan|status|fix [package|all]",
    )

    if _SKILL_PATH.is_file():
        ctx.register_skill(
            "vuln-triage",
            _SKILL_PATH,
            description="How to read RookGuard findings and decide between fix and accept-risk.",
        )

    logger.info("rookguard loaded")
