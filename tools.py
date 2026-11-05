"""RookGuard — package inventory, CVE scanning and guided remediation.

Track, scan, fix: snapshot the packages installed on the host where the agent
runs, check them against the cve.now catalog, report prioritized findings with
fixed versions, and apply user-approved upgrades.

Design notes
------------
* Durable state lives in ``plugin_db("rookguard")`` (never the install tree);
  exported scan reports go to ``plugin_data_dir("rookguard")``.
* The cve.now MCP tool (``mcp__cve_now__check_stack``) is called through
  ``ctx.dispatch_tool`` so it uses the parent agent's approvals. When it is
  missing or fails, the plugin falls back to a direct HTTPS JSON-RPC call to
  the same service and says so in the result.
* Handlers always return a JSON string and never raise.
* This module deliberately imports nothing from Hermes at import time: the
  catalog validator imports it with a bare interpreter. Hermes-only imports
  are lazy, inside helpers.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

PLUGIN_NAME = "rookguard"
MCP_TOOL = "mcp__cve_now__check_stack"
CVE_NOW_MCP_URL = "https://mcp.cve.now/mcp"
MAX_PACKAGES_PER_CHECK = 100
DEFAULT_COMMAND_TIMEOUT = 300

# Storage ecosystems (what the user sees) and the corresponding cve.now/OSV
# ecosystem names. cve.now currently indexes pypi/npm/cargo and friends; distro
# ecosystems are inventoried but reported as not scanned rather than guessed at.
ECOSYSTEMS = ("dpkg", "pip", "npm", "cargo")
CVE_ECOSYSTEM = {
    "dpkg": "deb",
    "deb": "deb",
    "pip": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
}
# Ecosystems check_stack accepts today. Keep this permissive: an unknown value
# is dropped with a warning instead of failing the whole batch.
SCANNABLE = frozenset({"pypi", "npm", "cargo", "go", "rubygems", "composer", "nuget", "hex", "pub", "swift"})

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
REVERSE_SEVERITY = {v: k for k, v in SEVERITY_ORDER.items()}

_briefing_lock = threading.Lock()
_briefings: dict[str, str] = {}


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


def _error(message: Any, **extra: Any) -> str:
    return _json({"ok": False, "error": str(message), **extra})


def _as_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", ""}
    return bool(value)


def _normalize_ecosystem(value: str) -> str:
    return CVE_ECOSYSTEM.get(str(value or "").strip().lower(), str(value or "").strip().lower())


def _severity_rank(rating: Any, cvss: Any = None) -> int:
    name = str(rating or "").strip().lower()
    if name in SEVERITY_ORDER:
        return SEVERITY_ORDER[name]
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return 0
    if score >= 9.0:
        return SEVERITY_ORDER["critical"]
    if score >= 7.0:
        return SEVERITY_ORDER["high"]
    if score >= 4.0:
        return SEVERITY_ORDER["medium"]
    return SEVERITY_ORDER["low"]


def _rating(rating: Any, cvss: Any = None) -> str:
    name = str(rating or "").strip().lower()
    if name in SEVERITY_ORDER and name != "unknown":
        return name
    return REVERSE_SEVERITY.get(_severity_rank(None, cvss), "unknown")


def _version_key(version: str) -> tuple:
    """Loose numeric ordering good enough to pick the newest fixed version."""
    parts = re.split(r"[.+~:-]", str(version or ""))
    key: list[int] = []
    for part in parts:
        match = re.match(r"^(\d+)", part)
        key.append(int(match.group(1)) if match else -1)
    return tuple(key)


def _newest(versions: Iterable[Any]) -> str:
    cleaned = [str(v).strip() for v in versions if str(v or "").strip()]
    if not cleaned:
        return ""
    return max(cleaned, key=_version_key)


def _as_args(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


_SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    name        TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'snapshot',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (name, ecosystem)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    ecosystems  TEXT NOT NULL DEFAULT '[]',
    checked     INTEGER NOT NULL DEFAULT 0,
    affected    INTEGER NOT NULL DEFAULT 0,
    mode        TEXT,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER NOT NULL,
    cve_id             TEXT NOT NULL,
    ecosystem          TEXT NOT NULL,
    package            TEXT NOT NULL,
    version            TEXT NOT NULL DEFAULT '',
    title              TEXT,
    cvss               REAL,
    rating             TEXT NOT NULL DEFAULT 'unknown',
    kev                INTEGER NOT NULL DEFAULT 0,
    actively_exploited INTEGER NOT NULL DEFAULT 0,
    public_exploit     INTEGER NOT NULL DEFAULT 0,
    fixed_versions     TEXT NOT NULL DEFAULT '[]',
    fixed_version      TEXT NOT NULL DEFAULT '',
    url                TEXT,
    status             TEXT NOT NULL DEFAULT 'open',
    resolved_at        TEXT,
    fix_output         TEXT,
    UNIQUE (scan_id, cve_id, package, ecosystem)
);

CREATE INDEX IF NOT EXISTS findings_status ON findings (status, rating);
CREATE INDEX IF NOT EXISTS findings_package ON findings (package, ecosystem);
"""


def _db() -> sqlite3.Connection:
    """Open the plugin database and make sure the schema exists."""
    from plugins.plugin_storage import plugin_db  # lazy: Hermes-only

    conn = plugin_db(PLUGIN_NAME)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def _upsert_package(conn: sqlite3.Connection, name: str, ecosystem: str, version: str, source: str) -> None:
    now = _now()
    conn.execute(
        """
        INSERT INTO packages (name, ecosystem, version, source, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(name, ecosystem) DO UPDATE SET
            version = CASE WHEN excluded.version <> '' THEN excluded.version ELSE packages.version END,
            source = excluded.source,
            last_seen = excluded.last_seen
        """,
        (name, ecosystem, version or "", source, now, now),
    )


def _reconcile_ecosystem(conn: sqlite3.Connection, ecosystem: str, packages: list[dict]) -> int:
    """Drop inventory rows for a *successful* snapshot that no longer exist.

    Only call this for an ecosystem whose collector ran successfully: a failed
    pip/npm/dpkg call must not wipe the inventory. Returns the number removed.
    """
    seen = {
        str(package.get("name") or "").strip()
        for package in packages
        if str(package.get("name") or "").strip()
    }
    existing = {
        str(row[0])
        for row in conn.execute("SELECT name FROM packages WHERE ecosystem = ?", (ecosystem,))
    }
    stale = sorted(existing - seen)
    for start in range(0, len(stale), 500):
        chunk = stale[start : start + 500]
        placeholders = ", ".join("?" for _ in chunk)
        conn.execute(
            f"DELETE FROM packages WHERE ecosystem = ? AND name IN ({placeholders})",
            [ecosystem, *chunk],
        )
    return len(stale)


# --------------------------------------------------------------------------- #
# Inventory: dpkg, pip, npm
# --------------------------------------------------------------------------- #


def _run_command_sync(argv: list[str], timeout: int = 60) -> str:
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = result.stdout or ""
    if result.returncode != 0 and not output.strip():
        detail = (result.stderr or "").strip()
        raise RuntimeError(f"{argv[0]} exited {result.returncode}" + (f": {detail}" if detail else ""))
    return output


def _parse_dpkg_output(text: str) -> list[dict]:
    packages: list[dict] = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, version, status = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if not name or "installed" not in status:
            continue
        packages.append({"name": name, "version": version, "ecosystem": "dpkg"})
    return packages


def _parse_pip_output(text: str) -> list[dict]:
    try:
        parsed = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    packages: list[dict] = []
    for item in parsed if isinstance(parsed, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            packages.append({"name": name, "version": str(item.get("version") or ""), "ecosystem": "pip"})
    return packages


def _parse_npm_output(text: str) -> list[dict]:
    try:
        parsed = json.loads(text or "{}")
    except (TypeError, ValueError):
        return []
    deps = parsed.get("dependencies") if isinstance(parsed, dict) else {}
    packages: list[dict] = []
    for name, meta in (deps or {}).items():
        if not isinstance(meta, dict):
            continue
        packages.append({"name": str(name), "version": str(meta.get("version") or ""), "ecosystem": "npm"})
    return packages


def _collect_dpkg() -> list[dict]:
    text = _run_command_sync(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"],
        timeout=60,
    )
    return _parse_dpkg_output(text)


def _collect_pip() -> list[dict]:
    for argv in (
        [sys.executable, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
        ["pip", "list", "--format=json", "--disable-pip-version-check"],
        ["pip3", "list", "--format=json", "--disable-pip-version-check"],
    ):
        try:
            return _parse_pip_output(_run_command_sync(argv, timeout=120))
        except FileNotFoundError:
            continue
    raise FileNotFoundError("pip not found")


def _collect_npm() -> list[dict]:
    for argv in (
        ["npm", "ls", "-g", "--json", "--depth=0"],
        ["npm", "list", "-g", "--json", "--depth=0"],
    ):
        try:
            return _parse_npm_output(_run_command_sync(argv, timeout=120))
        except FileNotFoundError:
            continue
    raise FileNotFoundError("npm not found")


_COLLECTORS: dict[str, Callable[[], list[dict]]] = {
    "dpkg": _collect_dpkg,
    "pip": _collect_pip,
    "npm": _collect_npm,
}


def rookguard_inventory(args: Optional[dict] = None, **kwargs: Any) -> str:
    """Snapshot installed packages and persist them in the inventory."""
    args = _as_args(args)
    requested = args.get("ecosystems") or list(_COLLECTORS)
    if isinstance(requested, str):
        requested = [requested]
    requested = [str(e).strip().lower() for e in requested if str(e).strip()]
    unknown = [e for e in requested if e not in _COLLECTORS]
    requested = [e for e in requested if e in _COLLECTORS] or list(_COLLECTORS)

    try:
        conn = _db()
    except Exception as exc:
        return _error(f"RookGuard storage unavailable: {exc}")

    collected: dict[str, list[dict]] = {}
    errors: dict[str, str] = {}
    for ecosystem in requested:
        try:
            collected[ecosystem] = _COLLECTORS[ecosystem]()
        except subprocess.TimeoutExpired:
            errors[ecosystem] = "timed out"
        except FileNotFoundError:
            errors[ecosystem] = "command not found"
        except Exception as exc:  # never raise out of a tool handler
            errors[ecosystem] = str(exc)

    total = 0
    removed: dict[str, int] = {}
    stored_at = _now()
    try:
        with conn:
            for ecosystem, packages in collected.items():
                for package in packages:
                    _upsert_package(conn, package["name"], ecosystem, package.get("version", ""), "snapshot")
                removed[ecosystem] = _reconcile_ecosystem(conn, ecosystem, packages)
                total += len(packages)
    except Exception as exc:
        return _error(f"failed to store inventory: {exc}")

    counts = {ecosystem: len(packages) for ecosystem, packages in collected.items()}
    if unknown:
        errors["unknown_ecosystems"] = ", ".join(unknown)
    return _json(
        {
            "ok": not errors or total > 0,
            "packages": total,
            "ecosystems": counts,
            "removed": {ecosystem: count for ecosystem, count in removed.items() if count},
            "errors": errors,
            "snapshot_at": stored_at,
            "next": "Run rookguard_scan to check these packages against cve.now.",
        }
    )


# --------------------------------------------------------------------------- #
# Install/upgrade tracking (post_tool_call hook)
# --------------------------------------------------------------------------- #

_SEPARATORS = {"&&", "||", ";", "|", "&"}
_PIP_FLAGS_WITH_VALUE = {"--index-url", "-i", "--extra-index-url", "--trusted-host", "--target", "-t", "--python", "--proxy", "-c", "--constraint"}
_APT_FLAGS_WITH_VALUE = {"-o", "-t", "--target-release", "--option", "--config-file", "-c"}


def _tokens_for(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _after(tokens: list[str], index: int) -> list[str]:
    out: list[str] = []
    for token in tokens[index:]:
        if token in _SEPARATORS:
            break
        out.append(token)
    return out


def _split_pinned(token: str) -> tuple[str, str]:
    """Split an install token into name and an exact version, when pinned.

    ``pkg==1.2`` (pip), ``pkg@1.2`` (npm, including ``@scope/pkg@1.2``) and
    ``pkg=1.2`` (apt) carry an exact version. Range specifiers such as
    ``pkg>=1.2`` are not exact, so the version is left empty.
    """
    token = token.strip()
    if not token:
        return "", ""
    if token.startswith("@"):
        split_at = token.find("@", 1)
        if split_at > 0:
            return token[:split_at], token[split_at + 1 :]
        return token, ""
    match = re.match(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)(.*)$", token)
    if not match:
        return token, ""
    name, rest = match.group(1), match.group(2)
    if rest.startswith("=="):
        return name, rest[2:]
    if rest.startswith("=") and not rest.startswith((">=", "<=", "~=", "!=")):
        return name, rest[1:]
    if rest.startswith("@"):
        return name, rest[1:]
    return name, ""


def _clean_package(token: str) -> str:
    token = token.strip().strip("'\"")
    if not token or token.startswith("-") or token in {".", ".."}:
        return ""
    if token.startswith((".", "/", "~/")) or token.endswith((".deb", ".whl", ".tar.gz", ".zip")):
        return ""
    if "://" in token or token.startswith("git+") or token.startswith("file:"):
        return ""
    return token


def _detect_installs(command: str) -> list[dict]:
    """Return packages named by install/upgrade commands in *command*."""
    tokens = _tokens_for(command)
    found: list[dict] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        # pip install / python -m pip install
        if token in {"pip", "pip3"} or (token == "pip" and i and tokens[i - 1] == "-m"):
            install_at = i + 1
            if install_at < len(tokens) and tokens[install_at] == "install":
                for raw in _after(tokens, install_at + 1):
                    if raw in _PIP_FLAGS_WITH_VALUE or raw.startswith("-"):
                        continue
                    name, version = _split_pinned(_clean_package(raw))
                    if name:
                        found.append({"name": name.split("[", 1)[0], "version": version, "ecosystem": "pip"})
        # apt-get / apt install
        if token in {"apt-get", "apt"} and i + 1 < len(tokens) and tokens[i + 1] == "install":
            for raw in _after(tokens, i + 2):
                if raw in _APT_FLAGS_WITH_VALUE or raw.startswith("-"):
                    continue
                name, version = _split_pinned(_clean_package(raw))
                if name:
                    found.append({"name": name, "version": version, "ecosystem": "dpkg"})
        # npm install -g / npm i --global
        if token == "npm":
            sub = tokens[i + 1] if i + 1 < len(tokens) else ""
            if sub in {"install", "i", "add"}:
                tail = _after(tokens, i + 2)
                if "-g" in tail or "--global" in tail:
                    for raw in tail:
                        if raw.startswith("-"):
                            continue
                        cleaned = _clean_package(raw)
                        if not cleaned:
                            continue
                        name, version = _split_pinned(cleaned)
                        if name:
                            found.append({"name": name, "version": version, "ecosystem": "npm"})
        # cargo install
        if token == "cargo" and i + 1 < len(tokens) and tokens[i + 1] == "install":
            tail = _after(tokens, i + 2)
            version = ""
            names: list[str] = []
            j = 0
            while j < len(tail):
                raw = tail[j]
                if raw == "--version" and j + 1 < len(tail):
                    version = tail[j + 1]
                    j += 2
                    continue
                if raw.startswith("-"):
                    j += 1
                    continue
                names.append(raw)
                j += 1
            for raw in names:
                name, pinned = _split_pinned(_clean_package(raw))
                if name:
                    found.append({"name": name, "version": pinned or version, "ecosystem": "cargo"})
        i += 1
    # De-duplicate within one command, keeping the most specific version.
    deduped: dict[tuple[str, str], dict] = {}
    for item in found:
        key = (item["ecosystem"], item["name"])
        if key not in deduped or (item.get("version") and not deduped[key].get("version")):
            deduped[key] = item
    return list(deduped.values())


def record_installs(tool_name: str, args: Any, result: Any = None, **kwargs: Any) -> None:
    """``post_tool_call`` hook: remember packages installed or upgraded by the agent."""
    if tool_name not in {"terminal", "run_terminal_cmd"}:
        return
    command = _as_args(args).get("command") or ""
    if not isinstance(command, str) or not command:
        return
    packages = _detect_installs(command)
    if not packages:
        return
    try:
        conn = _db()
        with conn:
            for package in packages:
                _upsert_package(
                    conn,
                    package["name"],
                    package["ecosystem"],
                    package.get("version", ""),
                    "hook",
                )
    except Exception:
        logger.warning("RookGuard could not record install deltas", exc_info=True)


# --------------------------------------------------------------------------- #
# cve.now
# --------------------------------------------------------------------------- #


def _affected_from_payload(payload: Any) -> Optional[dict]:
    """Normalize any supported cve.now response shape to ``{affected, checked}``."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    if payload.get("isError"):
        return None
    if payload.get("error"):
        return None
    # MCP envelope: {"result": {"content": [{"type": "text", "text": "..."}]}}
    if "jsonrpc" in payload and isinstance(payload.get("result"), dict):
        payload = payload["result"]
        if payload.get("isError"):
            return None
    if "content" in payload and isinstance(payload["content"], list):
        texts = [
            item.get("text", "")
            for item in payload["content"]
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        # Servers may append a non-JSON attribution line after the payload, so
        # parse each text block on its own instead of joining them.
        parsed_blocks = []
        for text in texts:
            try:
                candidate = json.loads(text)
            except (TypeError, ValueError):
                continue
            if isinstance(candidate, dict):
                parsed_blocks.append(candidate)
        if not parsed_blocks:
            return None
        payload = next((block for block in parsed_blocks if "affected" in block), parsed_blocks[0])
    if not isinstance(payload, dict) or "affected" not in payload:
        return None
    affected = payload.get("affected")
    if not isinstance(affected, list):
        return None
    return {"affected": affected, "checked": payload.get("checked", 0)}


def _direct_check_stack(packages: list[dict], timeout: int = 90) -> dict:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "check_stack", "arguments": {"packages": packages}},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        CVE_NOW_MCP_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"{PLUGIN_NAME}/0.0.1",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URL
        raw = response.read().decode("utf-8", "replace")
    parsed = _affected_from_payload(raw)
    if parsed is None:
        raise RuntimeError("cve.now returned an unexpected response")
    return parsed


def _dispatch_check_stack(dispatch: Callable, packages: list[dict]) -> dict:
    raw = dispatch(MCP_TOOL, {"packages": packages})
    parsed = _affected_from_payload(raw)
    if parsed is None:
        raise RuntimeError("cve.now MCP tool returned an error")
    return parsed


def _check_stack(packages: list[dict], dispatch: Optional[Callable] = None) -> dict:
    """Check one batch, preferring the MCP tool and falling back to HTTPS."""
    if dispatch is not None:
        try:
            result = _dispatch_check_stack(dispatch, packages)
            return {**result, "mode": "mcp"}
        except Exception as exc:
            logger.info("RookGuard: cve.now MCP unavailable (%s); falling back to HTTPS", exc)
    result = _direct_check_stack(packages)
    return {**result, "mode": "https"}


def _packages_for_check(conn: sqlite3.Connection, ecosystems: Optional[set[str]]) -> tuple[list[dict], list[str]]:
    rows = conn.execute("SELECT name, ecosystem, version FROM packages ORDER BY ecosystem, name").fetchall()
    packages: list[dict] = []
    skipped: list[str] = []
    for row in rows:
        ecosystem = str(row["ecosystem"])
        if ecosystems and ecosystem not in ecosystems:
            continue
        cve_ecosystem = _normalize_ecosystem(ecosystem)
        if cve_ecosystem not in SCANNABLE:
            skipped.append(ecosystem)
            continue
        version = str(row["version"] or "").strip()
        if not version:
            continue
        packages.append({"ecosystem": cve_ecosystem, "name": str(row["name"]), "version": version})
    return packages, sorted(set(skipped))


def _store_findings(
    conn: sqlite3.Connection,
    scan_id: int,
    affected: list[dict],
    scanned_packages: Iterable[dict] = (),
) -> int:
    stored = 0
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        name = str(package.get("name") or "").strip()
        cve_ecosystem = str(package.get("ecosystem") or "").strip().lower()
        if not name:
            continue
        ecosystem = "pip" if cve_ecosystem == "pypi" else cve_ecosystem
        version = str(package.get("version") or "")
        severity = item.get("severity") if isinstance(item.get("severity"), dict) else {}
        fixed = item.get("fixed") if isinstance(item.get("fixed"), list) else []
        conn.execute(
            """
            INSERT OR IGNORE INTO findings (
                scan_id, cve_id, ecosystem, package, version, title, cvss, rating,
                kev, actively_exploited, public_exploit, fixed_versions, fixed_version,
                url, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
            """,
            (
                scan_id,
                str(item.get("id") or ""),
                ecosystem,
                name,
                version,
                str(item.get("title") or ""),
                severity.get("cvss"),
                _rating(item.get("rating"), severity.get("cvss")),
                1 if item.get("kev") else 0,
                1 if item.get("activelyExploited") else 0,
                1 if item.get("publicExploit") else 0,
                json.dumps([str(v) for v in fixed if v]),
                _newest(fixed),
                str(item.get("url") or ""),
            ),
        )
        stored += 1
    # A package that was checked and is no longer affected must not keep its old
    # open findings; a package that was affected keeps exactly this scan's rows.
    for package in scanned_packages:
        ecosystem = _normalize_ecosystem(str(package.get("ecosystem") or ""))
        name = str(package.get("name") or "")
        if not name:
            continue
        conn.execute(
            "UPDATE findings SET status = 'superseded' "
            "WHERE status = 'open' AND package = ? AND ecosystem = ? AND scan_id <> ?",
            (name, "pip" if ecosystem == "pypi" else ecosystem, scan_id),
        )
    return stored


def _export_report(scan_id: int, payload: dict) -> Optional[str]:
    try:
        from plugins.plugin_storage import plugin_data_dir  # lazy: Hermes-only

        reports = plugin_data_dir(PLUGIN_NAME) / "scans"
        reports.mkdir(parents=True, exist_ok=True)
        path = reports / f"scan-{scan_id}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        return str(path)
    except Exception:
        logger.debug("RookGuard could not export the scan report", exc_info=True)
        return None


def rookguard_scan(args: Optional[dict] = None, *, dispatch: Optional[Callable] = None, **kwargs: Any) -> str:
    """Check the current inventory against cve.now and store findings."""
    args = _as_args(args)
    requested = args.get("ecosystems")
    if isinstance(requested, str):
        requested = [requested]
    ecosystem_filter = {str(e).strip().lower() for e in requested} if requested else None
    min_severity = str(args.get("min_severity") or "low").strip().lower()
    if min_severity not in SEVERITY_ORDER:
        min_severity = "low"

    try:
        conn = _db()
    except Exception as exc:
        return _error(f"RookGuard storage unavailable: {exc}")

    packages, skipped = _packages_for_check(conn, ecosystem_filter)
    if not packages:
        return _error(
            "No scannable packages in the inventory. Run rookguard_inventory first.",
            skipped_ecosystems=skipped,
        )

    started = _now()
    cursor = conn.execute(
        "INSERT INTO scans (started_at, status, ecosystems) VALUES (?, 'running', ?)",
        (started, json.dumps(sorted(ecosystem_filter) if ecosystem_filter else [])),
    )
    scan_id = int(cursor.lastrowid)
    conn.commit()

    affected: list[dict] = []
    checked = 0
    modes: set[str] = set()
    checked_packages: list[dict] = []
    cve_error: Optional[str] = None
    try:
        for start in range(0, len(packages), MAX_PACKAGES_PER_CHECK):
            chunk = packages[start : start + MAX_PACKAGES_PER_CHECK]
            result = _check_stack(chunk, dispatch=dispatch)
            affected.extend(result.get("affected") or [])
            checked += int(result.get("checked") or len(chunk))
            checked_packages.extend(chunk)
            modes.add(str(result.get("mode") or "unknown"))
    except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
        cve_error = str(exc)
        logger.warning("RookGuard scan failed: %s", exc)
    except Exception as exc:  # defensive: a tool handler must not raise
        cve_error = str(exc)
        logger.warning("RookGuard scan failed", exc_info=True)

    stored = 0
    try:
        with conn:
            if cve_error is None:
                stored = _store_findings(conn, scan_id, affected, checked_packages)
            conn.execute(
                "UPDATE scans SET finished_at = ?, status = ?, checked = ?, affected = ?, mode = ?, error = ? "
                "WHERE id = ?",
                (
                    _now(),
                    "ok" if cve_error is None else "failed",
                    checked,
                    stored,
                    ",".join(sorted(modes)) or None,
                    cve_error,
                    scan_id,
                ),
            )
    except Exception as exc:
        return _error(f"failed to store scan results: {exc}", scan_id=scan_id)

    if cve_error is not None:
        return _error(
            "cve.now check failed. Install the cve.now MCP server (or allow HTTPS egress) and retry.",
            scan_id=scan_id,
            detail=cve_error,
            skipped_ecosystems=skipped,
        )

    visible = [
        item
        for item in affected
        if _severity_rank(item.get("rating"), (item.get("severity") or {}).get("cvss"))
        >= SEVERITY_ORDER[min_severity]
    ]
    counts: dict[str, int] = {name: 0 for name in SEVERITY_ORDER if name != "unknown"}
    for item in visible:
        counts[_rating(item.get("rating"), (item.get("severity") or {}).get("cvss"))] += 1
    report_path = _export_report(
        scan_id,
        {
            "scan_id": scan_id,
            "started_at": started,
            "finished_at": _now(),
            "checked": checked,
            "affected": visible,
            "skipped_ecosystems": skipped,
            "mode": ",".join(sorted(modes)),
        },
    )
    return _json(
        {
            "ok": True,
            "scan_id": scan_id,
            "checked": checked,
            "affected": len(visible),
            "by_severity": counts,
            "min_severity": min_severity,
            "mode": ",".join(sorted(modes)),
            "skipped_ecosystems": skipped,
            "report": report_path,
            "next": "Run rookguard_status for details, then rookguard_fix to upgrade.",
        }
    )


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #


def _finding_where(
    *,
    severity: Optional[str] = None,
    ecosystem: Optional[str] = None,
    include_fixed: bool = False,
) -> tuple[str, list[Any]]:
    clauses = ["1 = 1"]
    params: list[Any] = []
    if include_fixed:
        clauses.append("status IN ('open', 'fixed')")
    else:
        clauses.append("status = 'open'")
    if ecosystem:
        clauses.append("ecosystem = ?")
        params.append(ecosystem)
    if severity:
        clauses.append(
            "CASE rating WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END >= ?"
        )
        params.append(SEVERITY_ORDER[severity])
    return " AND ".join(clauses), params


def _finding_summary(
    conn: sqlite3.Connection,
    *,
    severity: Optional[str] = None,
    ecosystem: Optional[str] = None,
    include_fixed: bool = False,
) -> dict:
    """Exact per-severity counts over all matching findings (no page limit)."""
    where, params = _finding_where(severity=severity, ecosystem=ecosystem, include_fixed=include_fixed)
    summary: dict[str, int] = {name: 0 for name in ("critical", "high", "medium", "low", "unknown")}
    total = 0
    for row in conn.execute(
        f"SELECT rating, COUNT(*) AS n FROM findings WHERE {where} GROUP BY rating", params
    ).fetchall():
        rating = str(row["rating"] or "unknown")
        count = int(row["n"])
        summary[rating] = summary.get(rating, 0) + count
        total += count
    return {"total": total, "summary": summary}


def _query_findings(
    conn: sqlite3.Connection,
    *,
    severity: Optional[str] = None,
    ecosystem: Optional[str] = None,
    include_fixed: bool = False,
    limit: int = 50,
) -> tuple[list[dict], int]:
    where, params = _finding_where(severity=severity, ecosystem=ecosystem, include_fixed=include_fixed)
    total = int(conn.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", params).fetchone()[0])
    rows = conn.execute(
        f"""
        SELECT id, scan_id, cve_id, ecosystem, package, version, title, cvss, rating,
               kev, actively_exploited, public_exploit, fixed_versions, fixed_version,
               url, status, resolved_at
        FROM findings
        WHERE {where}
        ORDER BY CASE rating WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                 cvss DESC, package ASC
        LIMIT ?
        """,
        [*params, max(1, min(int(limit), 500))],
    ).fetchall()
    return [_row_to_dict(row) for row in rows], total


def _last_scan(conn: sqlite3.Connection) -> Optional[dict]:
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return _row_to_dict(row) if row else None


def rookguard_status(args: Optional[dict] = None, **kwargs: Any) -> str:
    """Report open findings grouped by severity."""
    args = _as_args(args)
    severity = str(args.get("severity") or "").strip().lower() or None
    if severity and severity not in SEVERITY_ORDER:
        severity = None
    ecosystem = str(args.get("ecosystem") or "").strip().lower() or None
    include_fixed = _as_bool(args.get("include_fixed"), False)
    try:
        limit = int(args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50

    try:
        conn = _db()
        rows, total = _query_findings(
            conn,
            severity=severity,
            ecosystem=ecosystem,
            include_fixed=include_fixed,
            limit=limit,
        )
        exact = _finding_summary(
            conn,
            severity=severity,
            ecosystem=ecosystem,
            include_fixed=include_fixed,
        )
        last_scan = _last_scan(conn)
    except Exception as exc:
        return _error(f"RookGuard storage unavailable: {exc}")

    # ``groups`` is the requested page; ``summary``/``total`` cover every match.
    groups: dict[str, list[dict]] = {name: [] for name in ("critical", "high", "medium", "low", "unknown")}
    for row in rows:
        groups.setdefault(row.get("rating") or "unknown", []).append(row)
    summary = exact["summary"]
    total = exact["total"]
    return _json(
        {
            "ok": True,
            "total": total,
            "returned": len(rows),
            "summary": summary,
            "groups": groups,
            "last_scan": last_scan,
            "hint": (
                "Run rookguard_fix with a package name or all=true to upgrade."
                if total
                else "No open findings. Run rookguard_scan to refresh."
            ),
        }
    )


# --------------------------------------------------------------------------- #
# Fix
# --------------------------------------------------------------------------- #


def build_upgrade_command(ecosystem: str, package: str, version: str, use_sudo: bool = True) -> list[str]:
    """Return the argv for upgrading *package* in *ecosystem*."""
    ecosystem = str(ecosystem or "").strip().lower()
    if ecosystem == "pip":
        argv = [sys.executable, "-m", "pip", "install", "--upgrade", f"{package}=={version}"]
        return ["sudo", "-H", *argv] if use_sudo else argv
    if ecosystem == "dpkg":
        # Distro fixed versions rarely match the vendor version cve.now reports;
        # let apt pick the repository's fixed build.
        argv = ["apt-get", "install", "-y", "--only-upgrade", package]
        return ["sudo", *argv] if use_sudo else argv
    if ecosystem == "npm":
        argv = ["npm", "install", "-g", f"{package}@{version}"]
        return ["sudo", *argv] if use_sudo else argv
    if ecosystem == "cargo":
        # cargo installs into ~/.cargo/bin; sudo would be wrong here.
        return ["cargo", "install", package, "--version", version, "--force"]
    raise ValueError(f"unsupported ecosystem: {ecosystem}")


def _targets(conn: sqlite3.Connection, package: Optional[str], ecosystem: Optional[str]) -> list[dict]:
    clauses = ["status = 'open'", "fixed_version <> ''"]
    params: list[Any] = []
    if package:
        clauses.append("package = ?")
        params.append(package)
    if ecosystem:
        clauses.append("ecosystem = ?")
        params.append(ecosystem)
    rows = conn.execute(
        f"SELECT id, ecosystem, package, version, fixed_version "
        f"FROM findings WHERE {' AND '.join(clauses)}",
        params,
    ).fetchall()
    grouped: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (str(row["ecosystem"]), str(row["package"]))
        target = grouped.setdefault(
            key,
            {
                "ecosystem": key[0],
                "package": key[1],
                "fixed_version": "",
                "scanned_version": "",
                "finding_ids": [],
            },
        )
        target["finding_ids"].append(int(row["id"]))
        target["fixed_version"] = _newest([target["fixed_version"], str(row["fixed_version"])])
        scanned = str(row["version"] or "").strip()
        if scanned and not target["scanned_version"]:
            target["scanned_version"] = scanned
    return list(grouped.values())


def _version_probe_command(ecosystem: str, package: str) -> list[str]:
    """Return the argv that reports the installed version of one package."""
    if ecosystem == "pip":
        return [sys.executable, "-m", "pip", "show", package]
    if ecosystem == "npm":
        return ["npm", "ls", "-g", package, "--json", "--depth=0"]
    if ecosystem == "dpkg":
        return ["dpkg-query", "-W", "-f=${Version}", package]
    if ecosystem == "cargo":
        return ["cargo", "install", "--list"]
    raise ValueError(f"unsupported ecosystem: {ecosystem}")


def _extract_installed_version(ecosystem: str, package: str, output: str) -> str:
    """Parse the output of ``_version_probe_command`` for one package."""
    if ecosystem == "pip":
        for line in (output or "").splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() == "version":
                return value.strip()
        return ""
    if ecosystem == "npm":
        try:
            parsed = json.loads(output or "{}")
        except (TypeError, ValueError):
            return ""
        deps = parsed.get("dependencies") if isinstance(parsed, dict) else {}
        meta = (deps or {}).get(package)
        return str((meta or {}).get("version") or "").strip() if isinstance(meta, dict) else ""
    if ecosystem == "dpkg":
        for line in (output or "").splitlines():
            if line.strip():
                return line.strip()
        return ""
    if ecosystem == "cargo":
        pattern = re.compile(rf"^\s*{re.escape(package)}\s+v?([^\s:]+)")
        for line in (output or "").splitlines():
            match = pattern.match(line)
            if match:
                return match.group(1).strip()
        return ""
    return ""


def _probe_installed_version(ecosystem: str, package: str, dispatch: Callable) -> dict:
    """Ask the terminal what version of ``package`` is actually installed."""
    try:
        argv = _version_probe_command(ecosystem, package)
    except ValueError as exc:
        return {"installed_version": "", "command": "", "exit_code": None, "error": str(exc)}
    command = shlex.join(argv)
    try:
        outcome = _parse_terminal_result(
            dispatch("terminal", {"command": command, "timeout": DEFAULT_COMMAND_TIMEOUT})
        )
    except Exception as exc:
        return {"installed_version": "", "command": command, "exit_code": None, "error": str(exc)}
    if not outcome.get("ok"):
        return {
            "installed_version": "",
            "command": command,
            "exit_code": outcome.get("exit_code"),
            "error": outcome.get("error") or "version probe failed",
        }
    installed = _extract_installed_version(ecosystem, package, outcome.get("output") or "")
    return {
        "installed_version": installed,
        "command": command,
        "exit_code": outcome.get("exit_code"),
        "error": None if installed else "could not read the installed version",
    }


def _verify_upgrade(target: dict, installed_version: str) -> tuple[bool, Optional[str]]:
    """Decide whether an exit-0 upgrade actually closed the finding.

    A zero exit code only says the package manager accepted the command. The
    finding is closed only when the installed version moved off the scanned
    version and reached the advertised fixed version.
    """
    installed = str(installed_version or "").strip()
    fixed = str(target.get("fixed_version") or "").strip()
    scanned = str(target.get("scanned_version") or "").strip()
    if not installed:
        return False, "could not read the installed version after the upgrade"
    if scanned and installed == scanned:
        return False, f"package is still at the vulnerable version {scanned}"
    if fixed and _version_key(installed) < _version_key(fixed):
        return False, f"installed version {installed} is older than the fixed version {fixed}"
    return True, None


def _parse_terminal_result(raw: Any) -> dict:
    payload = raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return {"ok": False, "output": raw, "exit_code": None, "error": "unparseable terminal result"}
    if not isinstance(payload, dict):
        return {"ok": False, "output": str(raw), "exit_code": None, "error": "unexpected terminal result"}
    exit_code = payload.get("exit_code", payload.get("returncode", payload.get("exitCode")))
    error = payload.get("error")
    if error:
        return {"ok": False, "output": str(payload.get("output") or ""), "exit_code": exit_code, "error": str(error)}
    if isinstance(exit_code, int):
        return {"ok": exit_code == 0, "output": str(payload.get("output") or ""), "exit_code": exit_code, "error": None}
    if isinstance(payload.get("ok"), bool):
        return {"ok": payload["ok"], "output": str(payload.get("output") or ""), "exit_code": exit_code, "error": None}
    return {"ok": False, "output": str(payload.get("output") or ""), "exit_code": exit_code,
            "error": "could not determine command outcome"}


def _mark_findings(conn: sqlite3.Connection, finding_ids: list[int], status: str, output: str) -> None:
    conn.executemany(
        "UPDATE findings SET status = ?, resolved_at = ?, fix_output = ? WHERE id = ?",
        [(status, _now(), (output or "")[:4000], finding_id) for finding_id in finding_ids],
    )


def rookguard_fix(
    args: Optional[dict] = None,
    *,
    dispatch: Optional[Callable] = None,
    use_sudo: bool = True,
    **kwargs: Any,
) -> str:
    """Upgrade one package or every approved package, via the terminal tool."""
    args = _as_args(args)
    package = str(args.get("package") or "").strip() or None
    ecosystem = str(args.get("ecosystem") or "").strip().lower() or None
    fix_all = _as_bool(args.get("all"), False)
    if not package and not fix_all:
        return _error("Pass a package name or all=true.")
    if package and fix_all:
        return _error("Pass either package or all=true, not both.")
    if ecosystem and ecosystem not in ECOSYSTEMS:
        return _error(f"unsupported ecosystem: {ecosystem}")

    try:
        conn = _db()
        targets = _targets(conn, package, ecosystem)
    except Exception as exc:
        return _error(f"RookGuard storage unavailable: {exc}")

    if not targets:
        return _error(
            "No open finding with a fixed version matches that selection. "
            "Run rookguard_scan and rookguard_status first."
        )
    if dispatch is None:
        return _error("The terminal tool is not available; cannot run upgrades.")

    fixed: list[dict] = []
    failed: list[dict] = []
    for target in targets:
        try:
            argv = build_upgrade_command(
                target["ecosystem"],
                target["package"],
                target["fixed_version"],
                use_sudo=use_sudo,
            )
        except ValueError as exc:
            failed.append({**target, "error": str(exc)})
            continue
        command = shlex.join(argv)
        try:
            outcome = _parse_terminal_result(
                dispatch("terminal", {"command": command, "timeout": DEFAULT_COMMAND_TIMEOUT})
            )
        except Exception as exc:
            outcome = {"ok": False, "output": "", "error": str(exc), "exit_code": None}

        probe: dict = {"installed_version": "", "command": "", "exit_code": None, "error": None}
        verified = False
        verification_error: Optional[str] = None
        if outcome.get("ok"):
            probe = _probe_installed_version(target["ecosystem"], target["package"], dispatch)
            verified, verification_error = _verify_upgrade(target, probe["installed_version"])

        status = "fixed" if verified else "failed"
        verification = {
            "verified": verified,
            "installed_version": probe.get("installed_version") or "",
            "command": probe.get("command") or "",
            "error": verification_error,
        }
        output = outcome.get("output") or ""
        if not verified and probe.get("error"):
            output = f"{output}\nverification: {probe['error']}".strip()
        try:
            with conn:
                _mark_findings(conn, target["finding_ids"], status, output)
        except Exception:
            logger.warning("RookGuard could not record the fix outcome", exc_info=True)
        record = {
            **target,
            "command": command,
            "exit_code": outcome.get("exit_code"),
            "output": output[-2000:],
            "error": outcome.get("error") or (None if verified else verification_error),
            "verified_version": probe.get("installed_version") or "",
            "verification": verification,
        }
        (fixed if verified else failed).append(record)

    return _json(
        {
            "ok": bool(fixed),
            "fixed": fixed,
            "failed": failed,
            "next": (
                "Run rookguard_status to confirm the findings cleared, then rookguard_scan."
                if fixed
                else "Nothing was verified as fixed; check the command output and the "
                "installed versions, then retry."
            ),
        }
    )


# --------------------------------------------------------------------------- #
# Session briefing (on_session_start / pre_llm_call)
# --------------------------------------------------------------------------- #


def build_briefing(stale_after_hours: int = 12) -> Optional[str]:
    """Return a short briefing when the last scan is stale or findings remain."""
    try:
        conn = _db()
        last_scan = _last_scan(conn)
        exact = _finding_summary(conn)
    except Exception:
        return None
    total = exact["total"]
    if not last_scan and not total:
        return None

    stale = True
    finished = last_scan.get("finished_at") if last_scan else None
    if finished:
        try:
            when = datetime.fromisoformat(str(finished).replace("Z", "+00:00"))
            stale = (datetime.now(timezone.utc) - when).total_seconds() > stale_after_hours * 3600
        except (TypeError, ValueError):
            stale = True
    if not stale and not total:
        return None

    counts = exact["summary"]
    lines = ["RookGuard briefing:"]
    if last_scan:
        lines.append(
            f"- Last scan: {finished or last_scan.get('started_at')} "
            f"({last_scan.get('status')}, {last_scan.get('affected')} affected)"
        )
    else:
        lines.append("- No scan has run yet.")
    if total:
        lines.append(
            "- Open findings: "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low."
        )
        lines.append("- Run /rookguard status for details, or /rookguard fix <pkg> to upgrade.")
    elif stale:
        lines.append("- Run /rookguard scan to refresh the vulnerability picture.")
    return "\n".join(lines)


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    """Warm the briefing cache; ``pre_llm_call`` injects it on the first turn."""
    briefing = build_briefing()
    if not briefing:
        return
    with _briefing_lock:
        _briefings[str(session_id or "default")] = briefing


def on_pre_llm_call(session_id: str = "", is_first_turn: bool = False, **kwargs: Any) -> Optional[dict]:
    """Inject the RookGuard briefing into the first user message of a session."""
    if not is_first_turn:
        return None
    key = str(session_id or "default")
    with _briefing_lock:
        briefing = _briefings.pop(key, None)
    if briefing is None:
        briefing = build_briefing()
    return {"context": briefing} if briefing else None


# --------------------------------------------------------------------------- #
# Slash command
# --------------------------------------------------------------------------- #


def _human_status(payload: dict) -> str:
    if not payload.get("ok"):
        return f"RookGuard: {payload.get('error', 'unknown error')}"
    total = payload.get("total", 0)
    if not total:
        return "RookGuard: no open findings."
    summary = payload.get("summary") or {}
    lines = [
        f"RookGuard: {total} open finding(s) — "
        f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        f"{summary.get('medium', 0)} medium, {summary.get('low', 0)} low."
    ]
    for severity in ("critical", "high", "medium", "low", "unknown"):
        for item in (payload.get("groups") or {}).get(severity) or []:
            fix = item.get("fixed_version") or "no fixed version"
            lines.append(
                f"  [{severity}] {item.get('cve_id')} {item.get('package')} "
                f"{item.get('version')} -> {fix}"
            )
    lines.append("Fix one with /rookguard fix <package>, or all with /rookguard fix all.")
    return "\n".join(lines)


def make_command_handler(handlers: dict[str, Callable]) -> Callable[[str], str]:
    """Build the ``/rookguard`` slash-command handler around the tool handlers."""

    def handler(raw_args: str = "") -> str:
        parts = _tokens_for(raw_args or "")
        subcommand = parts[0].lower() if parts else "status"
        rest = parts[1:]
        if subcommand in {"inventory", "scan"}:
            payload = json.loads(handlers[f"rookguard_{subcommand}"]({}))
            if not payload.get("ok"):
                return f"RookGuard {subcommand}: {payload.get('error', 'failed')}"
            if subcommand == "inventory":
                return (
                    f"RookGuard inventory: {payload.get('packages', 0)} package(s) recorded "
                    f"({payload.get('ecosystems')})."
                )
            return (
                f"RookGuard scan: {payload.get('affected', 0)} finding(s) across "
                f"{payload.get('checked', 0)} package(s)."
            )
        if subcommand == "status":
            return _human_status(json.loads(handlers["rookguard_status"]({})))
        if subcommand == "fix":
            if not rest:
                return "Usage: /rookguard fix <package>|all"
            args = {"all": True} if rest[0].lower() == "all" else {"package": rest[0]}
            payload = json.loads(handlers["rookguard_fix"](args))
            if not payload.get("ok"):
                return f"RookGuard fix: {payload.get('error', 'failed')}"
            fixed = payload.get("fixed") or []
            failed = payload.get("failed") or []
            lines = [f"RookGuard fix: {len(fixed)} succeeded, {len(failed)} failed."]
            for item in fixed:
                lines.append(
                    f"  upgraded {item.get('package')} -> "
                    f"{item.get('verified_version') or item.get('fixed_version')}"
                )
            for item in failed:
                lines.append(
                    f"  failed {item.get('package')}: "
                    f"{item.get('error') or 'not verified as fixed'}"
                )
            return "\n".join(lines)
        return "Usage: /rookguard inventory|scan|status|fix [package|all]"

    return handler


# --------------------------------------------------------------------------- #
# Registration helpers
# --------------------------------------------------------------------------- #


def build_handlers(ctx: Any) -> dict[str, Callable]:
    """Bind the tool handlers to a PluginContext (dispatch + config)."""
    dispatch = getattr(ctx, "dispatch_tool", None)
    try:
        configured = ctx.get_config("use_sudo", True)
    except Exception:
        configured = True
    use_sudo = _as_bool(configured, True)

    return {
        "rookguard_inventory": lambda args, **kwargs: rookguard_inventory(args, **kwargs),
        "rookguard_scan": lambda args, **kwargs: rookguard_scan(args, dispatch=dispatch, **kwargs),
        "rookguard_status": lambda args, **kwargs: rookguard_status(args, **kwargs),
        "rookguard_fix": lambda args, **kwargs: rookguard_fix(
            args, dispatch=dispatch, use_sudo=use_sudo, **kwargs
        ),
    }


__all__ = [
    "PLUGIN_NAME",
    "build_briefing",
    "build_handlers",
    "build_upgrade_command",
    "make_command_handler",
    "on_pre_llm_call",
    "on_session_start",
    "record_installs",
    "rookguard_fix",
    "rookguard_inventory",
    "rookguard_scan",
    "rookguard_status",
    "_detect_installs",
    "_parse_dpkg_output",
    "_parse_npm_output",
    "_parse_pip_output",
]
