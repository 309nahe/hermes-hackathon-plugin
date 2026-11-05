# UPDATE.md — workspace handoff for agentic coding

Last updated: 2026-11-05. `main` @ `7a002f4`. Tests: 35 passed.

## Repo
- `309nahe/hermes-hackathon-plugin` — RookGuard, a Hermes Agent plugin: package inventory, cve.now CVE scanning, guided remediation.
- Key files: `tools.py` (all handlers), `schemas.py`, `__init__.py`, `plugin.yaml` (`rookguard`, `0.0.1`), `plugin-catalog-entry.yaml` (draft, SHA still scaffold `129bcc0…`), `README.md`, `skills/vuln-triage/SKILL.md`, `tests/test_plugin.py`, `.github/workflows/ci.yml`.
- Tests load `__init__.py` as a package (`submodule_search_locations`); integration test derives plugin name from `plugin.yaml`.
- Validation: only expected `sudo_usage` caution. Upstream dpkg gap: https://github.com/sazabi/cve.now/issues/6 (OPEN).

## How to resume on a new workspace / VPS
```bash
git clone git@github.com:309nahe/hermes-hackathon-plugin.git && cd hermes-hackathon-plugin
git log --oneline -5; cat UPDATE.md
# quality gate (run from /tmp, NOT the repo root — local tools.py shadows Hermes tools):
cd /tmp && /tmp/hermes-agent/.venv/bin/python -m pytest -q /path/to/hermes-hackathon-plugin/tests/
# needs Hermes agent checkout with .venv at /tmp/hermes-agent (clone NousResearch/hermes-agent + uv sync --group dev if missing):
/tmp/hermes-agent/.venv/bin/hermes plugins validate /path/to/hermes-hackathon-plugin --install-deps
/tmp/hermes-agent/.venv/bin/ruff check --select F,E9 /path/to/hermes-hackathon-plugin
```
- Always `gh` for GitHub. Never push to `main` (except this file, see AGENTS.md). Branch per issue: `<type>/<n>-<slug>`, one PR per issue with `Closes #n`, do not merge.

## Done (merged)
- Base `5c3510c` `feat: implement RookGuard (track, scan, fix)` — inventory/scan/status/fix, hooks (`record_installs`, briefing), `/rookguard` command, vuln-triage skill, manifest/README alignment.
- #1 `ci: fail the workflow when pytest fails` (CLOSED, PR in base) — removed `|| true` + `continue-on-error` from `ci.yml`.
- #2 `fix(inventory): remove packages that are no longer installed` (CLOSED, PR in base) — `_reconcile_ecosystem` per ecosystem after successful snapshot; collectors raise on missing/failed commands; ghost-row + failed-collector + empty-snapshot tests.
- #3 `fix(fix): verify the upgrade closed the finding` (CLOSED, PR #16, commit `517a367`) — `_targets` splits `fixed_version`/`scanned_version`; `_version_probe_command`/`_extract_installed_version`/`_probe_installed_version`/`_verify_upgrade`; `rookguard_fix` probes via same `terminal` dispatch after exit 0, marks `fixed` only if verified else `failed` with `verified_version`/`verification`.
- #4 `fix(scan): resolve versions for hook-tracked packages` (CLOSED, PR #17, `aefc9ed`) — `_resolve_missing_versions` + `_resolve_package_version_local`; `rookguard_scan` resolves `""` versions (dispatch else local subprocess), persists, exposes `resolved_versions`/`unresolved_versions`; `_packages_for_check` → 3-tuple `(packages, skipped, unresolved)`.
- #5 `fix(status): compute severity counts from all findings` (CLOSED, PR #18, `b63456b`) — `_finding_where` + `_finding_summary` (`GROUP BY rating`, no limit); `rookguard_status` keeps `groups` as page but exact `summary`/`total`; `build_briefing` uses exact summary.
- `docs: add AGENTS.md` (PR #15, `165d5a1`) — gh-only, branch+PR, atomic issues, quality gate.

## Open backlog (suggested order)
- #6 `feat(scan): OSV fallback for dpkg` — cve.now rejects `deb`; query `api.osv.dev` for `Debian:*/Ubuntu:*`, reuse `_store_findings`; fixture-based, no live net.
- #11 `test: MCP dispatch, fallback, hook recording` — `_dispatch_check_stack` success/fallback, `_parse_terminal_result`, hook DB write, briefing staleness, command handlers.
- #10 `feat(scan): configurable cve.now endpoint/timeout/batch/retries` — `cve_now_url`, `request_timeout_seconds`, `batch_size`, `max_retries` + backoff.
- #9 `feat(storage): prune old scans/findings` — `retention_days` (default 90), keep latest scan.
- #8 `feat(fix): user-level (no-sudo) fix mode` — per-call `--user` / `use_sudo:false`, never sudo cargo.
- #7 `docs: macOS support (pip/npm only, no dpkg)`.
- #12 `chore: bump to 0.1.0` (both yamls, quoted).
- #13 `chore: pin 40-char SHA + open catalog PR` (fork `NousResearch/hermes-agent`, `plugin-catalog/rookguard.yaml`).
- #14 `submission: <90s demo + Typeform` (before Nov 11 2026 5 PM EST) — preseed `requests==2.28.0`, record inventory→scan→status→fix→briefing, post on X tagging `@NousResearch`.

## Caveats
- `plugin.yaml`/`plugin-catalog-entry.yaml` still `0.0.1` (#12). Catalog SHA still scaffold (#13).
- `dpkg` rows inventoried but skipped in scans until #6 or upstream fix.
- `cargo` never uses sudo. Briefing injects on first turn / session start.
