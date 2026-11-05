# RookGuard

> **Track, scan, fix.** Environment inventory, CVE scanning and guided
> remediation as a [Hermes Agent](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins)
> plugin.

RookGuard keeps an inventory of the packages installed on the host where the
agent runs, checks it against [cve.now](https://cve.now), presents prioritized
findings with fixed versions, and applies the upgrades you approve. A request
like "install code-server and expose it" becomes a tracked, auditable action.

## What it registers

| Surface | Component | Role |
| --- | --- | --- |
| Tool | `rookguard_inventory` | Snapshot dpkg/pip/npm packages into the durable inventory |
| Tool | `rookguard_scan` | Check the inventory against cve.now and store findings |
| Tool | `rookguard_status` | Findings grouped by severity, with fixed versions |
| Tool | `rookguard_fix` | Upgrade one package or all approved ones |
| Hook | `post_tool_call` | Detect `apt-get install`, `pip install`, `npm install -g`, `cargo install` and record deltas |
| Hook | `on_session_start` / `pre_llm_call` | Build and inject a short briefing on the first turn when a scan is stale or findings remain |
| Slash command | `/rookguard inventory\|scan\|status\|fix [package\|all]` | User-facing UX |
| Skill | `vuln-triage` | How to read findings, prioritize by KEV/CVSS/exploitation, and choose fix vs accept-risk |

Storage: `plugin_db("rookguard")` for the inventory, scans and findings;
`plugin_data_dir("rookguard")/scans/` for exported JSON reports.

## Requirements

- Hermes Agent `>=0.22.0`.
- `dpkg-query` (Debian/Ubuntu), `pip` and/or `npm` on the host. v1 targets
  Debian/Ubuntu plus pip and npm; other distros are a TODO.
- The [cve.now MCP server](https://mcp.cve.now/mcp) is optional. When the
  `mcp__cve_now__check_stack` tool is available RookGuard uses it; otherwise it
  falls back to a direct HTTPS JSON-RPC call to `https://mcp.cve.now/mcp`.
  cve.now is unauthenticated — no API key or stored credential.

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

## Usage

```text
/rookguard inventory      # snapshot dpkg, pip and npm
/rookguard scan           # check the inventory against cve.now
/rookguard status         # findings by severity, with fixed versions
/rookguard fix requests   # upgrade one package (user-approved)
/rookguard fix all        # upgrade every package with an available fix
```

The same actions are available as tools, so the model can run them on its own
when you ask "is this box vulnerable?" or "fix the openssl finding".

`rookguard_fix` executes the ecosystem upgrade command through the terminal
tool, so the agent's normal approval flow applies. Findings are marked `fixed`
only on a zero exit code; failures keep their output for triage. Upgrades are
never auto-approved in v1.

## Develop

```bash
make validate   # hermes plugins validate . --install-deps
make test       # pytest
make enable     # enables the plugin in ~/.hermes/config.yaml
```

Run tests from outside the repository directory so the local `tools.py` does not shadow Hermes's `tools` package:

- **Network calls:** cve.now, during scans only (MCP tool or direct HTTPS).
  No other endpoints, no telemetry.
- **Shell commands:** `dpkg-query`, `pip list`, `npm ls -g` for inventory;
  `apt-get`, `pip`, `npm`, `cargo` upgrades for fixes. Fixes are user-approved
  and use `sudo` by default (`use_sudo` config).
- **Background processes:** none in v1.
- **Stored credentials:** none. cve.now is unauthenticated.
- **Telemetry:** none; opt-in only if ever added.

## Disclosure

- The plugin loads as `hermes_plugins.rookguard`, so intra-plugin imports are
  relative (`from . import tools`).
- Tests load the plugin **as a package** (`submodule_search_locations`), the way
  Hermes does. Loading `tools.py` as a bare top-level module breaks relative
  imports and can shadow Hermes's `tools` package. Run tests from outside the
  repo directory: `cd /tmp && pytest /path/to/tests`.
- Quote `version` in `plugin.yaml` (`"0.0.1"`), otherwise YAML parses it as a
  number.
- `provides_tools` / `provides_hooks` must exactly match what `register()`
  registers; `hermes plugins validate` enforces it.
- Durable state never goes in the install tree: use `plugin_data_dir` /
  `plugin_db`.

## Known limitations / TODO

- Gateway push notification for the briefing.
- A user-level-only fix mode (no sudo).
- OS coverage beyond Debian/Ubuntu (dpkg), pip and npm.
- cve.now does not index distro (`.deb`) ecosystems through `check_stack`
  today, so dpkg packages are inventoried and reported as *skipped* during a
  scan instead of being matched against guessed data.
- Web dashboard and email digest.

## License

MIT
