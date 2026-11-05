"""Tests for hermes-hackathon-plugin."""

import json
import os
import sys
from pathlib import Path

import pytest

# Make the plugin importable when run from the repo root.
import importlib.util

_tools_path = Path(__file__).resolve().parents[1] / "tools.py"
_spec = importlib.util.spec_from_file_location("plugin_tools", _tools_path)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
ping_handler = _mod.ping_handler


def test_ping_handler_default():
    out = json.loads(ping_handler({}))
    assert out == {"pong": "hello, world"}


def test_ping_handler_name():
    out = json.loads(ping_handler({"name": "nana"}))
    assert out == {"pong": "hello, nana"}


# Integration test only runs when Hermes Agent is importable.
hermes_available = False
try:
    import hermes_cli.plugins  # noqa: F401

    hermes_available = True
except Exception:
    hermes_available = False


@pytest.mark.skipif(not hermes_available, reason="hermes-agent not installed")
def test_plugin_loads(tmp_path, monkeypatch):
    import os as _os

    hermes_home = tmp_path / "hermes"
    (hermes_home / "plugins").mkdir(parents=True)
    plugin_dir = hermes_home / "plugins" / "hermes-hackathon-plugin"
    plugin_dir.symlink_to(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    import hermes_yaml as yaml

    cfg = {"plugins": {"enabled": ["hermes-hackathon-plugin"]}}
    (hermes_home / "config.yaml").write_text(yaml.safe_dump(cfg))

    from hermes_cli.plugins import PluginManager

    pm = PluginManager()
    pm.discover_and_load()
    assert "hermes-hackathon-plugin" in pm._plugins

