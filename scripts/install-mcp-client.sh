#!/usr/bin/env bash
# Merge Stockpiler MCP entry into a Cursor mcp.json config.
set -euo pipefail

URL=""
TOKEN=""
CONFIG="${HOME}/.cursor/mcp.json"

usage() {
    cat <<EOF
Usage: $0 --url URL [--token TOKEN] [--config PATH]

  --url URL       MCP server URL (e.g. http://stockpiler.example:1337/mcp)
  --token TOKEN   Optional bearer token (production)
  --config PATH   Cursor mcp.json path (default: ~/.cursor/mcp.json)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --config) CONFIG="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$URL" ]]; then
    echo "error: --url is required" >&2
    usage
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi

mkdir -p "$(dirname "$CONFIG")"

export STOCKPILER_MCP_URL="$URL"
export STOCKPILER_MCP_TOKEN="$TOKEN"
export STOCKPILER_MCP_CONFIG="$CONFIG"

python3 <<'PY'
import json
import os
from pathlib import Path

url = os.environ["STOCKPILER_MCP_URL"]
token = os.environ.get("STOCKPILER_MCP_TOKEN", "").strip()
config_path = Path(os.environ["STOCKPILER_MCP_CONFIG"]).expanduser()

if config_path.exists():
    data = json.loads(config_path.read_text())
else:
    data = {}

if not isinstance(data, dict):
    raise SystemExit(f"error: {config_path} is not a JSON object")

servers = data.setdefault("mcpServers", {})
if not isinstance(servers, dict):
    raise SystemExit("error: mcpServers must be an object")

entry = {"url": url}
if token:
    entry["headers"] = {"Authorization": f"Bearer {token}"}

servers["stockpiler"] = entry
config_path.write_text(json.dumps(data, indent=2) + "\n")
print(f"Updated {config_path}")
print(json.dumps({"stockpiler": entry}, indent=2))
PY

echo
echo "Restart Cursor (or reload MCP servers) so the stockpiler tools appear."
