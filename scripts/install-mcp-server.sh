#!/usr/bin/env bash
# Install Stockpiler MCP server: venv, deps, env file, systemd unit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="stockpiler-mcp"
ENV_PATH="/etc/stockpiler-mcp.env"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
VENV_DIR="$REPO_ROOT/mcp/.venv"

ROOT_ARG=""
SERVICE_USER="${SUDO_USER:-${USER:-stockpiler}}"
MODE="dev"
HOST="0.0.0.0"
PORT="1337"
NON_INTERACTIVE=0

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --root PATH           STOCKPILER_ROOT (data directory)
  --user NAME           systemd service user (default: \$SUDO_USER or \$USER)
  --mode dev|production STOCKPILER_MCP_MODE (default: dev)
  --host ADDR           bind address (default: 0.0.0.0)
  --port N              bind port (default: 1337)
  --non-interactive     require --root; do not prompt
  -h, --help            show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --root) ROOT_ARG="$2"; shift 2 ;;
        --user) SERVICE_USER="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: run as root (sudo) so systemd and /etc can be updated" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found" >&2
    exit 1
fi

PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_OK="$(python3 -c 'import sys; print(int(sys.version_info >= (3, 11)))')"
if [[ "$PY_OK" != "1" ]]; then
    echo "error: Python 3.11+ required (found $PY_VER)" >&2
    exit 1
fi

if [[ -z "$ROOT_ARG" ]]; then
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        echo "error: --root is required with --non-interactive" >&2
        exit 1
    fi
    read -r -p "STOCKPILER_ROOT path: " ROOT_ARG
fi
if [[ -z "$ROOT_ARG" ]]; then
    echo "error: STOCKPILER_ROOT is required" >&2
    exit 1
fi
mkdir -p "$ROOT_ARG"
ROOT_ARG="$(cd "$ROOT_ARG" && pwd)"

if [[ "$MODE" != "dev" && "$MODE" != "production" ]]; then
    echo "error: --mode must be dev or production" >&2
    exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "error: service user '$SERVICE_USER' does not exist" >&2
    exit 1
fi

echo "==> Creating venv at $VENV_DIR"
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$REPO_ROOT/mcp/requirements.txt"
VENV_PYTHON="$VENV_DIR/bin/python"
deactivate

if [[ ! -f "$ENV_PATH" ]]; then
    echo "==> Installing $ENV_PATH"
    sed \
        -e "s|^STOCKPILER_ROOT=.*|STOCKPILER_ROOT=$ROOT_ARG|" \
        -e "s|^STOCKPILER_MCP_HOST=.*|STOCKPILER_MCP_HOST=$HOST|" \
        -e "s|^STOCKPILER_MCP_PORT=.*|STOCKPILER_MCP_PORT=$PORT|" \
        -e "s|^STOCKPILER_MCP_MODE=.*|STOCKPILER_MCP_MODE=$MODE|" \
        "$REPO_ROOT/systemd/stockpiler-mcp.env.example" > "$ENV_PATH"
    chmod 600 "$ENV_PATH"
else
    echo "==> Keeping existing $ENV_PATH (not overwritten)"
fi

echo "==> Installing $UNIT_PATH"
sed \
    -e "s|@REPO_ROOT@|$REPO_ROOT|g" \
    -e "s|@VENV_PYTHON@|$VENV_PYTHON|g" \
    -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
    "$REPO_ROOT/systemd/stockpiler-mcp.service" > "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo
echo "Installed Stockpiler MCP."
echo "  data root : $ROOT_ARG"
echo "  env file  : $ENV_PATH"
echo "  unit      : $UNIT_PATH"
echo "  user      : $SERVICE_USER"
echo
echo "Smoke checks:"
echo "  systemctl status $SERVICE_NAME --no-pager"
echo "  journalctl -u $SERVICE_NAME -n 50 --no-pager"
echo "  curl -sS -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:${PORT}/mcp"
echo
echo "Clients (dev):"
echo "  ./scripts/install-mcp-client.sh --url http://<this-host>:${PORT}/mcp"
echo
if [[ "$MODE" == "dev" ]]; then
    echo "Production later: edit $ENV_PATH (MODE=production, TLS paths, API keys),"
    echo "then: systemctl restart $SERVICE_NAME"
fi
if [[ "$MODE" == "production" ]]; then
    echo "WARNING: production mode requires STOCKPILER_TLS_CERT, STOCKPILER_TLS_KEY,"
    echo "and STOCKPILER_API_KEYS in $ENV_PATH before the service will stay up."
fi
