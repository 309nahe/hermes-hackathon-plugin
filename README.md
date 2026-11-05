# rookguard

Hermes Agent plugin for environment inventory, CVE scanning, and guided remediation.

Status: scaffolding. The plugin skeleton is in place; implementation is in progress. See the implementation plan in the project brief.

## What it does

rookguard keeps an inventory of packages installed on the host the agent runs on. It records what is added, with versions and source, when the agent or the user installs or upgrades software. It queries cve.now for vulnerabilities affecting that inventory and presents findings with proposed fix versions. The user approves fixes per package or in bulk; rookguard runs the upgrade commands.

## Commands

Slash commands (planned):

- `/rookguard inventory` — snapshot the environment (dpkg, pip, npm).
- `/rookguard scan` — query cve.now and store findings.
- `/rookguard status` — show findings grouped by severity with proposed fixes.
- `/rookguard fix [pkg|all]` — run upgrade commands (user-approved).

Tools (LLM-callable, planned): `rookguard_inventory`, `rookguard_scan`, `rookguard_status`, `rookguard_fix`.

A bundled skill `vuln-triage` explains how to read and prioritize findings.

## How it works

- Storage: SQLite via `plugin_db('rookguard')` (inventory, scans, findings). Durable across updates.
- Hooks: `post_tool_call` detects install/upgrade commands and records deltas; `on_session_start` injects a briefing when a scan is stale or findings are unaddressed.
- CVE data: cve.now MCP server (`mcp__cve_now__check_stack`), with graceful degradation if unavailable.
- Fixes run through the terminal tool with explicit approval. sudo is used by default; a user-level-only mode is a planned option.

## Requirements

- Hermes Agent (>= 0.22.0).
- cve.now MCP server recommended (plugin degrades without it).
- Debian/Ubuntu for v1 (dpkg); pip and npm for Python/Node packages.

## Install (development)

```bash
git clone https://github.com/309nahe/hermes-hackathon-plugin
cd hermes-hackathon-plugin
./scripts/bootstrap.sh
```

The bootstrap script links the repo into `$HERMES_HOME/plugins/rookguard`, enables it, and runs validation. Re-running is safe.

## Development

```bash
make validate   # hermes plugins validate . --install-deps
make test       # pytest (run from a neutral directory; see notes)
make doctor     # debug load issues
```

Run tests from outside the repository directory so the local `tools.py` does not shadow Hermes's `tools` package:

```bash
cd /tmp && pytest /path/to/rookguard/tests/
```

Intra-plugin imports must be relative (`from .schemas import ...`). The plugin is loaded by Hermes as `hermes_plugins.<slug>`.

## Disclosure

- Network calls: cve.now API during scan only. No other third parties.
- Shell commands: dpkg, pip, npm for inventory; apt-get, pip, npm for fixes (user-approved, sudo allowed).
- Background processes: none in v1.
- Stored credentials: none (cve.now is unauthenticated).
- Telemetry: none. Opt-in only if added later.

## Limitations (v1)

- OS coverage: Debian/Ubuntu + pip + npm only.
- Scheduling: session-start staleness check; true nightly cron is a planned option.
- No auto-approve of upgrades.
- No gateway push notification; context injection only.

## License

MIT
