#!/usr/bin/env bash
# One-script setup for a replicable dev environment.
# Idempotent: safe to re-run.
set -euo pipefail

PLUGIN_NAME="${PLUGIN_NAME:-hermes-hackathon-plugin}"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# 1. Prereqs
say "Checking prerequisites"
for bin in git python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing: $bin"; exit 1; }
done

if ! command -v hermes >/dev/null 2>&1; then
  echo "hermes not found. Install Hermes Agent first (see https://hermes-agent.nousresearch.com/docs/getting-started)."
  echo "  (script: scripts/install.sh in the NousResearch/hermes-agent repo)"
  exit 1
fi

# 2. HERMES_HOME
mkdir -p "$HERMES_HOME"
if [ ! -f "$HERMES_HOME/config.yaml" ]; then
  say "Creating minimal config.yaml"
  cat > "$HERMES_HOME/config.yaml" <<'EOF'
plugins:
  enabled: []
EOF
fi

# 3. Link plugin into HERMES_HOME/plugins (editable, live reload on restart)
PLUGIN_DIR="$HERMES_HOME/plugins/$PLUGIN_NAME"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -e "$PLUGIN_DIR" ] && [ ! -L "$PLUGIN_DIR" ]; then
  echo "Refusing to overwrite existing (non-symlink) $PLUGIN_DIR"
  exit 1
fi
ln -sfn "$REPO_DIR" "$PLUGIN_DIR"
say "Linked $REPO_DIR -> $PLUGIN_DIR"

# 4. Enable plugin
hermes plugins enable "$PLUGIN_NAME" || true

# 5. Validate
say "Running hermes plugins validate"
hermes plugins validate "$REPO_DIR" --install-deps

say "Done. Restart Hermes to load the plugin. Try: hermes plugins list"
