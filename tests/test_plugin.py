"""Tests for RookGuard (hermes-hackathon-plugin).

The handler modules are loaded as part of the plugin *package* (the way Hermes
loads ``hermes_plugins.<slug>``), never as a bare top-level ``tools`` module:
a bare module has no parent package, so intra-plugin relative imports fail and
the local ``tools.py`` can shadow Hermes's own ``tools`` package.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "rookguard_plugin_under_test"

_spec = importlib.util.spec_from_file_location(
    PACKAGE_NAME,
    PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)],
)
assert _spec is not None and _spec.loader is not None
_package = importlib.util.module_from_spec(_spec)
sys.modules[PACKAGE_NAME] = _package
_spec.loader.exec_module(_package)

tools = _package.tools
schemas = _package.schemas


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    connection = sqlite3.connect(tmp_path / "rookguard.db")
    connection.row_factory = sqlite3.Row
    tools._ensure_schema(connection)
    monkeypatch.setattr(tools, "_db", lambda: connection)
    yield connection
    connection.close()


def _seed_finding(conn, *, package="requests", ecosystem="pip", version="2.28.0",
                  cve="CVE-2023-32681", rating="medium", fixed="2.31.0", status="open"):
    conn.execute(
        """
        INSERT INTO findings (
            scan_id, cve_id, ecosystem, package, version, title, cvss, rating,
            fixed_versions, fixed_version, url, status
        ) VALUES (0, ?, ?, ?, ?, 'test finding', 6.1, ?, ?, ?, '', ?)
        """,
        (cve, ecosystem, package, version, rating, json.dumps([fixed]), fixed, status),
    )
    conn.commit()


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


def test_schemas_cover_the_four_documented_tools():
    names = {schema["name"] for schema in schemas.ROOKGUARD_SCHEMAS}
    assert names == {
        "rookguard_inventory",
        "rookguard_scan",
        "rookguard_status",
        "rookguard_fix",
    }
    for schema in schemas.ROOKGUARD_SCHEMAS:
        assert schema["description"].strip()
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"]["additionalProperties"] is False


def test_fix_schema_requires_package_or_all():
    params = schemas.ROOKGUARD_FIX_SCHEMA["parameters"]
    assert params["anyOf"]
    assert params["properties"]["all"]["default"] is False


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #


def test_parse_dpkg_output_skips_removed_packages():
    text = (
        "curl\t7.88.1-10\tinstall ok installed\n"
        "oldpkg\t1.0\tdeinstall ok config-files\n"
        "openssl\t3.0.11-1\tinstall ok installed\n"
        "malformed line\n"
    )
    packages = tools._parse_dpkg_output(text)
    assert [(p["name"], p["version"]) for p in packages] == [
        ("curl", "7.88.1-10"),
        ("openssl", "3.0.11-1"),
    ]


def test_parse_pip_and_npm_output():
    pip = tools._parse_pip_output('[{"name": "requests", "version": "2.28.0"}]')
    assert pip == [{"name": "requests", "version": "2.28.0", "ecosystem": "pip"}]
    npm = tools._parse_npm_output('{"dependencies": {"lodash": {"version": "4.17.20"}}}')
    assert npm == [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]
    assert tools._parse_pip_output("not json") == []


def test_detect_installs_across_ecosystems():
    command = (
        "sudo apt-get install -y curl=7.88.1-10 && "
        "pip install requests==2.28.0 'urllib3>=2' && "
        "npm install -g lodash@4.17.20 && "
        "cargo install ripgrep --version 13.0.0"
    )
    found = {(item["ecosystem"], item["name"]): item["version"] for item in tools._detect_installs(command)}
    assert found[("dpkg", "curl")] == "7.88.1-10"
    assert found[("pip", "requests")] == "2.28.0"
    assert found[("pip", "urllib3")] == ""
    assert found[("npm", "lodash")] == "4.17.20"
    assert found[("cargo", "ripgrep")] == "13.0.0"


def test_detect_installs_ignores_local_npm_install():
    assert tools._detect_installs("npm install lodash") == []


def test_build_upgrade_command_respects_sudo_and_ecosystem():
    assert tools.build_upgrade_command("pip", "requests", "2.31.0", use_sudo=False) == [
        sys.executable, "-m", "pip", "install", "--upgrade", "requests==2.31.0",
    ]
    dpkg = tools.build_upgrade_command("dpkg", "openssl", "3.0.11", use_sudo=True)
    assert dpkg[:2] == ["sudo", "apt-get"]
    assert "openssl" in dpkg
    npm = tools.build_upgrade_command("npm", "lodash", "4.18.0", use_sudo=True)
    assert npm[:2] == ["sudo", "npm"]
    cargo = tools.build_upgrade_command("cargo", "ripgrep", "13.0.0", use_sudo=True)
    assert cargo[0] == "cargo"


def test_affected_from_payload_ignores_trailing_attribution():
    inner = '{"checked": 1, "affected": [{"id": "CVE-1"}]}'
    envelope = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [
            {"type": "text", "text": inner},
            {"type": "text", "text": "Source: cve.now, built and run by Sazabi"},
        ]},
    })
    parsed = tools._affected_from_payload(envelope)
    assert parsed == {"checked": 1, "affected": [{"id": "CVE-1"}]}


def test_affected_from_payload_rejects_errors():
    assert tools._affected_from_payload('{"jsonrpc":"2.0","result":{"content":[],"isError":true}}') is None
    assert tools._affected_from_payload("not json") is None


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #


def test_inventory_stores_packages(conn, monkeypatch):
    monkeypatch.setitem(tools._COLLECTORS, "dpkg", lambda: [
        {"name": "curl", "version": "7.88.1-10", "ecosystem": "dpkg"},
    ])
    payload = json.loads(tools.rookguard_inventory({"ecosystems": ["dpkg"]}))
    assert payload["ok"] is True
    assert payload["packages"] == 1
    row = conn.execute("SELECT name, version, source FROM packages").fetchone()
    assert (row["name"], row["version"], row["source"]) == ("curl", "7.88.1-10", "snapshot")


def test_inventory_removes_ghost_packages(conn, monkeypatch):
    tools._upsert_package(conn, "ghost", "pip", "1.0", "snapshot")
    tools._upsert_package(conn, "keep", "pip", "1.0", "snapshot")
    conn.commit()
    monkeypatch.setitem(tools._COLLECTORS, "pip", lambda: [
        {"name": "keep", "version": "2.0", "ecosystem": "pip"},
    ])

    payload = json.loads(tools.rookguard_inventory({"ecosystems": ["pip"]}))
    assert payload["removed"] == {"pip": 1}
    rows = {row["name"]: row["version"] for row in conn.execute("SELECT name, version FROM packages")}
    assert rows == {"keep": "2.0"}


def test_inventory_keeps_rows_when_collector_fails(conn, monkeypatch):
    tools._upsert_package(conn, "keep", "pip", "1.0", "snapshot")
    conn.commit()

    def boom():
        raise FileNotFoundError("pip not found")

    monkeypatch.setitem(tools._COLLECTORS, "pip", boom)
    payload = json.loads(tools.rookguard_inventory({"ecosystems": ["pip"]}))
    assert "pip" in payload["errors"]
    assert payload["removed"] == {}
    assert conn.execute("SELECT name FROM packages").fetchone()["name"] == "keep"


def test_inventory_empty_snapshot_clears_ecosystem(conn, monkeypatch):
    tools._upsert_package(conn, "gone", "npm", "1.0", "snapshot")
    conn.commit()
    monkeypatch.setitem(tools._COLLECTORS, "npm", lambda: [])

    payload = json.loads(tools.rookguard_inventory({"ecosystems": ["npm"]}))
    assert payload["packages"] == 0
    assert payload["removed"] == {"npm": 1}
    assert conn.execute("SELECT COUNT(*) FROM packages").fetchone()[0] == 0


def test_scan_resolves_missing_hook_version(conn, monkeypatch):
    tools._upsert_package(conn, "requests", "pip", "", "hook")
    conn.commit()
    seen = {}

    def fake_dispatch(name, args):
        assert name == "terminal"
        assert "pip show" in args["command"]
        return json.dumps({"output": "Name: requests\nVersion: 2.28.0\n", "exit_code": 0, "error": None})

    def fake_check(packages, dispatch=None):
        seen["packages"] = packages
        return {"checked": len(packages), "affected": [], "mode": "https"}

    monkeypatch.setattr(tools, "_check_stack", fake_check)
    payload = json.loads(tools.rookguard_scan({}, dispatch=fake_dispatch))
    assert payload["ok"] is True
    assert payload["checked"] == 1
    assert seen["packages"][0]["version"] == "2.28.0"
    assert payload["resolved_versions"] == [
        {"ecosystem": "pip", "name": "requests", "version": "2.28.0"}
    ]
    assert payload["unresolved_versions"] == []
    assert conn.execute("SELECT version FROM packages WHERE name = 'requests'").fetchone()["version"] == "2.28.0"


def test_scan_reports_unresolvable_version(conn, monkeypatch):
    tools._upsert_package(conn, "requests", "pip", "", "hook")
    conn.commit()

    def fake_dispatch(name, args):
        return json.dumps({"output": "", "exit_code": 1, "error": None})

    called = {"n": 0}

    def fake_check(packages, dispatch=None):
        called["n"] += 1
        return {"checked": 0, "affected": [], "mode": "https"}

    monkeypatch.setattr(tools, "_check_stack", fake_check)
    payload = json.loads(tools.rookguard_scan({}, dispatch=fake_dispatch))
    assert payload["ok"] is False
    assert called["n"] == 0
    assert payload["unresolved_versions"][0]["name"] == "requests"
    assert conn.execute("SELECT version FROM packages WHERE name = 'requests'").fetchone()["version"] == ""


def test_resolve_missing_versions_local_fallback(conn, monkeypatch):
    tools._upsert_package(conn, "requests", "pip", "", "hook")
    conn.commit()
    monkeypatch.setattr(
        tools, "_run_command_sync", lambda argv, timeout=60: "Name: requests\nVersion: 2.28.0\n"
    )
    resolution = tools._resolve_missing_versions(conn, dispatch=None)
    conn.commit()
    assert resolution["resolved"] == [{"ecosystem": "pip", "name": "requests", "version": "2.28.0"}]
    assert resolution["unresolved"] == []


def test_scan_stores_findings(conn, monkeypatch):
    tools._upsert_package(conn, "requests", "pip", "2.28.0", "snapshot")
    conn.commit()
    fake = {
        "checked": 1,
        "mode": "https",
        "affected": [
            {
                "id": "CVE-2023-32681",
                "title": "Proxy-Authorization leak",
                "severity": {"cvss": 6.1},
                "rating": "medium",
                "kev": False,
                "activelyExploited": False,
                "publicExploit": False,
                "package": {"ecosystem": "pypi", "name": "requests", "version": "2.28.0"},
                "fixed": ["2.31.0"],
                "url": "https://cve.now/CVE-2023-32681",
            }
        ],
    }
    monkeypatch.setattr(tools, "_check_stack", lambda packages, dispatch=None: fake)

    payload = json.loads(tools.rookguard_scan({}))
    assert payload["ok"] is True
    assert payload["affected"] == 1
    assert payload["by_severity"]["medium"] == 1

    row = conn.execute("SELECT * FROM findings").fetchone()
    assert row["cve_id"] == "CVE-2023-32681"
    assert row["ecosystem"] == "pip"
    assert row["fixed_version"] == "2.31.0"
    assert row["status"] == "open"


def test_scan_requires_inventory(conn, monkeypatch):
    payload = json.loads(tools.rookguard_scan({}))
    assert payload["ok"] is False
    assert "inventory" in payload["error"].lower()


def test_scan_skips_unsupported_ecosystems(conn, monkeypatch):
    tools._upsert_package(conn, "openssl", "dpkg", "3.0.11", "snapshot")
    tools._upsert_package(conn, "requests", "pip", "2.28.0", "snapshot")
    conn.commit()
    monkeypatch.setattr(tools, "_check_stack", lambda packages, dispatch=None: {
        "checked": len(packages), "affected": [], "mode": "https",
    })
    payload = json.loads(tools.rookguard_scan({}))
    assert payload["ok"] is True
    assert payload["checked"] == 1
    assert payload["skipped_ecosystems"] == ["dpkg"]


def test_rescan_supersedes_stale_findings(conn, monkeypatch):
    tools._upsert_package(conn, "requests", "pip", "2.32.0", "snapshot")
    _seed_finding(conn, cve="CVE-OLD", package="requests", version="2.28.0")
    monkeypatch.setattr(tools, "_check_stack", lambda packages, dispatch=None: {
        "checked": 1, "affected": [], "mode": "https",
    })
    payload = json.loads(tools.rookguard_scan({}))
    assert payload["ok"] is True
    assert payload["affected"] == 0
    assert conn.execute("SELECT status FROM findings").fetchone()["status"] == "superseded"
    assert json.loads(tools.rookguard_status({}))["total"] == 0


def test_status_groups_by_severity(conn):
    _seed_finding(conn, cve="CVE-1", rating="critical", package="openssl")
    _seed_finding(conn, cve="CVE-2", rating="medium", package="requests")

    payload = json.loads(tools.rookguard_status({}))
    assert payload["ok"] is True
    assert payload["total"] == 2
    assert payload["summary"]["critical"] == 1
    assert payload["summary"]["medium"] == 1
    assert payload["groups"]["critical"][0]["cve_id"] == "CVE-1"


def test_status_severity_filter(conn):
    _seed_finding(conn, cve="CVE-1", rating="critical", package="openssl")
    _seed_finding(conn, cve="CVE-2", rating="low", package="requests")
    payload = json.loads(tools.rookguard_status({"severity": "high"}))
    assert payload["total"] == 1
    assert payload["groups"]["critical"][0]["package"] == "openssl"


def _pip_probe_output(version):
    return f"Name: requests\nVersion: {version}\nLocation: /tmp/x\n"


def test_fix_runs_command_and_marks_finding(conn):
    _seed_finding(conn, package="requests", version="2.28.0", fixed="2.31.0")
    calls = []

    def fake_dispatch(name, args):
        calls.append((name, args))
        command = args.get("command", "")
        if "pip show" in command:
            return json.dumps({"output": _pip_probe_output("2.31.0"), "exit_code": 0, "error": None})
        return json.dumps({"output": "Successfully installed requests-2.31.0", "exit_code": 0, "error": None})

    payload = json.loads(tools.rookguard_fix({"package": "requests"}, dispatch=fake_dispatch, use_sudo=False))
    assert payload["ok"] is True
    assert payload["fixed"][0]["package"] == "requests"
    assert payload["fixed"][0]["verified_version"] == "2.31.0"
    assert payload["fixed"][0]["verification"]["verified"] is True
    assert calls[0][0] == "terminal"
    assert "requests==2.31.0" in calls[0][1]["command"]
    assert any("pip show" in c[1]["command"] for c in calls)

    row = conn.execute("SELECT status, fixed_version FROM findings").fetchone()
    assert row["status"] == "fixed"
    assert row["fixed_version"] == "2.31.0"


def test_fix_stale_version_stays_failed(conn):
    _seed_finding(conn, package="requests", version="2.28.0", fixed="2.31.0")

    def fake_dispatch(name, args):
        command = args.get("command", "")
        if "pip show" in command:
            return json.dumps({"output": _pip_probe_output("2.28.0"), "exit_code": 0, "error": None})
        return json.dumps({"output": "Requirement already satisfied", "exit_code": 0, "error": None})

    payload = json.loads(tools.rookguard_fix({"package": "requests"}, dispatch=fake_dispatch, use_sudo=False))
    assert payload["ok"] is False
    assert len(payload["fixed"]) == 0
    assert payload["failed"][0]["package"] == "requests"
    assert "2.28.0" in (payload["failed"][0]["error"] or "")
    assert conn.execute("SELECT status FROM findings").fetchone()["status"] == "failed"


def test_fix_probe_failure_stays_failed(conn):
    _seed_finding(conn, package="requests", version="2.28.0", fixed="2.31.0")

    def fake_dispatch(name, args):
        command = args.get("command", "")
        if "pip show" in command:
            return json.dumps({"output": "", "exit_code": 1, "error": None})
        return json.dumps({"output": "Successfully installed requests-2.31.0", "exit_code": 0, "error": None})

    payload = json.loads(tools.rookguard_fix({"package": "requests"}, dispatch=fake_dispatch, use_sudo=False))
    assert payload["ok"] is False
    assert payload["failed"][0]["verification"]["verified"] is False
    assert conn.execute("SELECT status FROM findings").fetchone()["status"] == "failed"


def test_fix_dpkg_requires_version_change(conn):
    _seed_finding(conn, package="openssl", ecosystem="dpkg", version="3.0.11-1", fixed="3.0.12-1")

    def fake_dispatch(name, args):
        command = args.get("command", "")
        if "dpkg-query" in command:
            return json.dumps({"output": "3.0.11-1", "exit_code": 0, "error": None})
        return json.dumps({"output": "openssl is already the newest version", "exit_code": 0, "error": None})

    payload = json.loads(tools.rookguard_fix({"package": "openssl"}, dispatch=fake_dispatch, use_sudo=False))
    assert payload["ok"] is False
    assert conn.execute("SELECT status FROM findings").fetchone()["status"] == "failed"


def test_verify_upgrade_compares_versions():
    target = {"package": "requests", "ecosystem": "pip", "fixed_version": "2.31.0", "scanned_version": "2.28.0"}
    assert tools._verify_upgrade(target, "2.31.0") == (True, None)
    # Newer than fixed is also fine.
    assert tools._verify_upgrade(target, "2.32.0")[0] is True
    ok, reason = tools._verify_upgrade(target, "2.28.0")
    assert ok is False and "2.28.0" in (reason or "")
    ok, reason = tools._verify_upgrade(target, "2.29.0")
    assert ok is False and "2.29.0" in (reason or "")
    ok, reason = tools._verify_upgrade(target, "")
    assert ok is False


def test_extract_installed_version_parsers():
    assert tools._extract_installed_version("pip", "requests", _pip_probe_output("2.31.0")) == "2.31.0"
    npm_out = json.dumps({"dependencies": {"lodash": {"version": "4.17.21"}}})
    assert tools._extract_installed_version("npm", "lodash", npm_out) == "4.17.21"
    assert tools._extract_installed_version("dpkg", "openssl", "3.0.12-1\n") == "3.0.12-1"
    cargo_out = "ripgrep v13.0.0:\n    ripgrep 13.0.0 (registry+https://github.com/rust-lang/crates.io-index)"
    assert tools._extract_installed_version("cargo", "ripgrep", cargo_out) == "13.0.0"


def test_fix_records_failure(conn):
    _seed_finding(conn, package="requests", fixed="2.31.0")
    payload = json.loads(
        tools.rookguard_fix(
            {"package": "requests"},
            dispatch=lambda name, args: json.dumps({"output": "boom", "exit_code": 1, "error": None}),
            use_sudo=False,
        )
    )
    assert payload["ok"] is False
    assert payload["failed"][0]["package"] == "requests"
    assert conn.execute("SELECT status FROM findings").fetchone()["status"] == "failed"


def test_fix_requires_selection(conn):
    payload = json.loads(tools.rookguard_fix({}, dispatch=lambda *a: "{}"))
    assert payload["ok"] is False
    assert "package" in payload["error"].lower()


# --------------------------------------------------------------------------- #
# Briefing and slash command
# --------------------------------------------------------------------------- #


def test_briefing_mentions_open_findings(conn):
    _seed_finding(conn, rating="critical")
    briefing = tools.build_briefing()
    assert briefing is not None
    assert "1 critical" in briefing
    assert "/rookguard status" in briefing


def test_command_handler_status(conn):
    _seed_finding(conn, rating="high", package="openssl")
    handler = tools.make_command_handler(tools.build_handlers(_FakeCtx()))
    out = handler("status")
    assert "RookGuard" in out
    assert "openssl" in out


class _FakeCtx:
    def get_config(self, key, default=None):
        return default

    def dispatch_tool(self, name, args, **kwargs):
        return json.dumps({"output": "", "exit_code": 0, "error": None})


# --------------------------------------------------------------------------- #
# Integration (only when Hermes Agent is importable)
# --------------------------------------------------------------------------- #

hermes_available = False
try:
    import hermes_cli.plugins  # noqa: F401
    import hermes_yaml  # noqa: F401

    hermes_available = True
except Exception:
    hermes_available = False


@pytest.mark.skipif(not hermes_available, reason="hermes-agent not installed")
def test_plugin_loads(tmp_path, monkeypatch):
    import hermes_yaml as yaml

    # The loader keys plugins by the name in plugin.yaml, not the repo name.
    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())
    plugin_name = manifest["name"]

    hermes_home = tmp_path / "hermes"
    (hermes_home / "plugins").mkdir(parents=True)
    plugin_dir = hermes_home / "plugins" / plugin_name
    plugin_dir.symlink_to(PLUGIN_DIR)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    (hermes_home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"enabled": [plugin_name]}})
    )

    from hermes_cli.plugins import PluginManager

    manager = PluginManager()
    manager.discover_and_load()
    assert plugin_name in manager._plugins
    assert {"rookguard_inventory", "rookguard_scan", "rookguard_status", "rookguard_fix"} <= manager._plugin_tool_names
