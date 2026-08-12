# Stockpiler installation

## Prerequisites

**Collector host (data machine)**

- Python 3.11+ (`python3.12` recommended; system `python3` may still be older)
  - Debian/Ubuntu: `sudo apt install python3.12 python3.12-venv`
  - Or pass an explicit interpreter: `sudo ./scripts/install-mcp-server.sh --python /usr/bin/python3.12 ...`
- `jq`, `git`
- Enough disk for the collection (1 TB+ recommended)
- systemd (for the MCP service)

**MCP clients**

- Cursor (or another MCP client that supports remote HTTP/SSE MCP)
- Network reachability to the MCP host on port **1337**

## Data root

Collector and MCP share one directory via `STOCKPILER_ROOT`.

Resolution order (script and MCP):

1. `$STOCKPILER_ROOT` if set
2. `<repo>/data` if that directory exists
3. `<repo>` if it already contains `CVE-*` or `PoC-in-GitHub` (legacy layout)
4. Otherwise create/use `<repo>/data`

Recommended layout:

```text
/opt/Stockpiler/              # git checkout (code)
/var/lib/stockpiler/data/     # STOCKPILER_ROOT (CVE-* + PoC-in-GitHub)
```

### Migrate a legacy tree

If everything currently lives next to `stockpiler.sh`:

```bash
export STOCKPILER_ROOT=/var/lib/stockpiler/data
mkdir -p "$STOCKPILER_ROOT"
cd /path/to/old/Stockpiler
mv CVE-* PoC-in-GitHub "$STOCKPILER_ROOT"/
```

## Collector

```bash
git clone <this-repo> /opt/Stockpiler
cd /opt/Stockpiler
export STOCKPILER_ROOT=/var/lib/stockpiler/data
./stockpiler.sh update
```

Optional cron (every 6 hours):

```cron
0 */6 * * * STOCKPILER_ROOT=/var/lib/stockpiler/data /opt/Stockpiler/stockpiler.sh update
```

Commands:

```bash
./stockpiler.sh update
./stockpiler.sh stat
./stockpiler.sh search CVE-2024-1234
```

## MCP server (data host)

```bash
cd /opt/Stockpiler
sudo ./scripts/install-mcp-server.sh --root /var/lib/stockpiler/data
```

What the script does:

1. Creates `mcp/.venv` and installs `mcp/requirements.txt`
2. Writes `/etc/stockpiler-mcp.env` **only if missing** (never overwrites secrets)
3. Installs `/etc/systemd/system/stockpiler-mcp.service` with absolute paths
4. `systemctl enable --now stockpiler-mcp`

Useful flags:

```bash
sudo ./scripts/install-mcp-server.sh \
  --root /var/lib/stockpiler/data \
  --user stockpiler \
  --mode dev \
  --host 0.0.0.0 \
  --port 1337 \
  --non-interactive
```

Ensure the service user can **read** `STOCKPILER_ROOT`. Keep the collector writable under a different account/cron if you want a read-only MCP user.

### Verify

```bash
systemctl status stockpiler-mcp --no-pager
journalctl -u stockpiler-mcp -n 50 --no-pager
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:1337/mcp
```

A `406` from a bare `curl` is normal (MCP requires specific client headers). The important part is that the port responds and the unit is active.

Default endpoint: `http://<host>:1337/mcp`

## MCP clients

### Install script

```bash
./scripts/install-mcp-client.sh --url http://stockpiler.example:1337/mcp
```

Production (TLS + API key):

```bash
./scripts/install-mcp-client.sh \
  --url https://stockpiler.example:1337/mcp \
  --token 'your-long-random-secret'
```

This merges a `stockpiler` entry into `~/.cursor/mcp.json` (other servers are preserved). Restart Cursor / reload MCP afterward.

### Manual config

Dev: see [examples/mcp.client.dev.json](../examples/mcp.client.dev.json)

Production: see [examples/mcp.client.prod.json](../examples/mcp.client.prod.json)

## Switching to production mode

Edit `/etc/stockpiler-mcp.env`:

```bash
STOCKPILER_MCP_MODE=production
STOCKPILER_TLS_CERT=/etc/stockpiler/tls/fullchain.pem
STOCKPILER_TLS_KEY=/etc/stockpiler/tls/privkey.pem
STOCKPILER_API_KEYS=long-random-secret,optional-second-key
```

Then:

```bash
sudo systemctl restart stockpiler-mcp
./scripts/install-mcp-client.sh --url https://HOST:1337/mcp --token 'long-random-secret'
```

The server refuses to start in production if cert, key, or API keys are missing.

Self-signed certificates: clients must trust the CA/cert (OS trust store or client-specific TLS settings).

## Optional: Nuclei coverage diff

Compare local PoC CVE IDs to [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates):

```bash
./scripts/diff-nuclei-cves.py \
  --root /var/lib/stockpiler/data \
  --templates ~/nuclei-templates \
  --clone-templates
```

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `STOCKPILER_ROOT does not exist` | Create the directory; set env in `/etc/stockpiler-mcp.env` |
| Permission denied reading PoCs | Service user needs read access to the data tree |
| Unit fails in production | Cert/key paths and `STOCKPILER_API_KEYS` must be set |
| Cursor shows no tools | Restart Cursor; confirm URL path ends with `/mcp`; check `systemctl status` |
| Auth failures (401) | Client `Authorization: Bearer …` must match a key in `STOCKPILER_API_KEYS` |
| Empty search results | Run `./stockpiler.sh update` on the collector; confirm you are querying the same root |

## Security notes

- PoCs may be malware. Do not execute blindly.
- Dev mode is plain HTTP with no auth — LAN only.
- Prefer production mode (TLS + API keys) when the service leaves a trusted segment.
