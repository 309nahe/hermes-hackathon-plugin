---
name: vuln-triage
description: "Use when RookGuard reports CVE findings: how to read them, prioritize by KEV/CVSS/exploitation, and choose fix vs accept-risk."
version: 1.0.0
author: 309nahe
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [Security, CVE, Triage, Remediation, RookGuard]
---

# Vulnerability triage with RookGuard

RookGuard inventories the host's packages, checks them against cve.now, and
reports findings with fixed versions. This skill is about the decision after
the scan: what to fix first, what can wait, and what should be accepted with
eyes open.

## Read the finding

Each finding carries:

- `cve_id` — CVE (or GHSA/OSV) identifier.
- `package` / `version` — what is installed on this host.
- `rating` — cve.now's severity band: critical, high, medium, low.
- `cvss` — numeric score when available.
- `kev` — the CVE is in CISA's Known Exploited Vulnerabilities catalog.
- `actively_exploited` — exploitation observed in the wild.
- `public_exploit` — a public exploit or Metasploit module exists.
- `fixed_version` — the version RookGuard would upgrade to.
- `url` — the cve.now entry for the full advisory.

`RookGuard never guesses a fixed version`: if `fixed_version` is empty, the
catalog has no fix and the finding is accept-risk or mitigate-outside-the-
package, not an upgrade.

## Prioritize

Work top-down:

1. **KEV or actively exploited, any severity.** Fix now. Exploitation beats
   the score.
2. **Critical / high with a public exploit and a fixed version.** Fix in the
   current session.
3. **Critical / high without evidence of exploitation.** Fix this week,
   especially for anything network-facing.
4. **Medium.** Batch with the next maintenance window; fix sooner if the
   package parses untrusted input (parsers, image/video codecs, archives,
   HTTP servers, auth libraries).
5. **Low, or no fixed version.** Accept-risk with a note, or mitigate at the
   boundary (disable the feature, restrict network access, drop privileges).

Exposure matters as much as severity: a critical CVE in a package that only
runs locally on trusted input is less urgent than a medium one in an
internet-facing daemon.

## Act

- **Fix one package:** `rookguard_fix` with `{"package": "<name>"}`.
- **Fix everything with an available fix:** `rookguard_fix` with
  `{"all": true}`.
- Slash-command equivalents: `/rookguard fix <package>` and
  `/rookguard fix all`.

Fixes run the ecosystem's upgrade command (apt-get, pip, npm, cargo) through
the terminal tool, so the user approves each run. Never claim a fix landed
without checking the returned `exit_code` and `output`; the finding is marked
`fixed` only on a zero exit.

After a fix: run `rookguard_scan` again, then `rookguard_status`. If the same
CVE is still open, the upgrade did not reach the fixed build (pinned version,
held package, wrong interpreter, or a container image that needs a rebuild).

## Accept-risk

Record why, and keep it short: the package is not reachable, the vulnerable
feature is disabled, the fixed version breaks a dependency, or the host is
disposable. Re-check on the next scan; do not suppress the finding silently.

## Never

- Never run an upgrade without user approval.
- Never auto-approve upgrades, batch or otherwise.
- Never invent a fixed version, a CVSS score, or a KEV flag. Only report what
  cve.now returned.
- Never patch a package by editing files in place; upgrade or mitigate.
