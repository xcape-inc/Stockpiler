# Stockpiler

XCAPE fork adds a PostgreSQL-backed Stockpile service for PTaaS. Existing
collector discovers GitHub PoCs. New service stores only validated normalized
Python PoCs. Each record defines exactly `run(payload)` and includes explicit
CVE/EUVD identifiers, source URL and commit, SHA-256, target constraints, and
conversion metadata.

Discovered repositories are untrusted. Discovery creates candidates; only
conversion output passing normalization contract enters `stockpile_pocs`.
Tailor executes selected PoCs inside its ephemeral container.

```bash
psql "$STOCKPILE_DSN" -f stockpiler/schema.sql
docker build -t xcape-stockpiler .
docker run --rm -p 8092:8092 \
  -e STOCKPILE_DSN -e STOCKPILE_WRITE_TOKEN xcape-stockpiler
```

`python -m stockpiler.discover --root "$STOCKPILER_ROOT"` continuously
refreshes GitHub through `STOCKPILER_UPDATE_COMMAND` and projects newly cloned
repositories into `stockpile_candidates`. `docker compose up api discover`
runs API and continuous crawler; converter profile is enabled after a converter
command is configured.
`python -m stockpiler.convert` invokes `STOCKPILER_CONVERTER_COMMAND` without a
shell. Converter receives provenance JSON on stdin and returns normalized source
as base64 JSON. Invalid Python or any signature other than `run(payload)` is
rejected and never enters active Stockpile.

### PTaaS normalization contract

Published rows use the schema in `stockpiler/schema.sql`. Each active row has a
stable `poc_id`, one or more `vulnerability_ids`, immutable source URL and
commit, target constraints, normalized Python bytes, SHA-256, metadata,
`conversion_status = 'validated'`, and `enabled = true`.

Normalized Python exposes one payload entry point:

```python
def run(payload: bytes) -> dict:
    ...
```

Tailor selects a row by both PoC ID and requested CVE/EUVD, verifies the digest,
and invokes `run(payload)`. Stockpiler never schedules or executes the PoC. The
PTaaS integration fixture uses `apache.cve-2021-41773-v1` to prove this contract
against an isolated Apache 2.4.49 container.
##### Created by M4x 5yn74x (Credited to <a href="https://github.com/nomi-sec/">Nomi-sec</a>)
#### Description: GitHub crawler that leverages the <a href="https://github.com/nomi-sec/PoC-in-GitHub">PoC-in-GitHub</a> repository to get the latest updates for the different public CVE PoCs. Includes a read-only MCP server so agents can pull PoC code into context over the LAN.

### Install

Full walkthrough: **[docs/INSTALL.md](docs/INSTALL.md)**

```bash
# Collector (data host)
export STOCKPILER_ROOT=/var/lib/stockpiler/data
./stockpiler.sh update

# MCP server (data host)
sudo ./scripts/install-mcp-server.sh --root /var/lib/stockpiler/data

# MCP client (Cursor machine)
./scripts/install-mcp-client.sh --url http://stockpiler.example:1337/mcp
```

Default MCP endpoint: `http://<host>:1337/mcp` (dev: HTTP, no auth). Production mode adds TLS + API keys via `/etc/stockpiler-mcp.env`.

### Tools
#### - `stockpiler.sh` — collector: update, stats, and search.

```
./stockpiler.sh update             # sync index + clone any missing PoCs (idempotent)
./stockpiler.sh stat               # collection / disk stats
./stockpiler.sh search <query>     # search local repos.txt (CVE ID or string)
```

`update` is safe to re-run: it pulls PoC-in-GitHub (or clones it on first run), ensures `repos.txt` is complete, and only clones repos that are not already on disk. Git operations are non-interactive (`GIT_TERMINAL_PROMPT=0`); failed clones skip the rate-limit delay.

Data lives under `STOCKPILER_ROOT` (or `./data`, or a legacy checkout that already contains `CVE-*`).

#### - MCP server (`mcp/server.py`) — read-only tools for remote clients: `search_cves`, `list_pocs`, `get_poc_context`, `read_poc_file`.

### Dependencies:
#### - `jq` - used to parse the JSON files for each CVE PoC within the PoC-in-GitHub repo
#### - `wc` - used to get the line count of all captured CVEs and PoCs. Should be installed on Debian by default, but you may want to double check.
#### - `du` - disk usage in `stat` (standard Unix utility).
#### - Python 3.11+ and packages in `mcp/requirements.txt` - for the MCP server (installed by `scripts/install-mcp-server.sh`).

### PoC-in-GitHub Dislaimer:
#### As mentioned on the repository, some of these published PoCs are fake, scams, or may contain malware to infect the user of the PoC once downloaded and executed on the user's computer. Please read the source code of every PoC before compiling/executing. Report all malicious repositories collected by their bot to their Issues section of their <a href="https://github.com/nomi-sec/PoC-in-GitHub/issues">repo</a>.

### Stockpiler Disclaimer:
#### The PoCs collected by this tool are for educational and for legitamate Cyber Security testing purposes only. Do not distribute this tool, or host publicly. The creator of this project shall not be held liable for the malicious use of this information or the PoCs collected by this project.

### Disk Space Warning:
#### This is a large collection, currently, as of today, over 312Gs in size and growing. Stockpiler will require at least 1 TB to cover the current collection as well as support more. Migrate to greater disk space as needed.

### Optimal Configuration
#### Given the frequency in which the PoC-in-GitHub is updated, we recommend setting up a cronjob to run every 6 hours. An example is shown below:

<code>0 */6 * * * STOCKPILER_ROOT=/var/lib/stockpiler/data /opt/Stockpiler/stockpiler.sh update</code>

### Stockpiler Stats
<pre>
1999 - 4
2000 - 4
2001 - 9
2002 - 16
2003 - 7
2004 - 10
2005 - 6
2006 - 12
2007 - 15
2008 - 19
2009 - 24
2010 - 29
2011 - 24
2012 - 39
2013 - 61
2014 - 99
2015 - 124
2016 - 159
2017 - 287
2018 - 422
2019 - 500
2020 - 677
2021 - 766
2022 - 831
2023 - 1121
2024 - 1316
2025 - 543
</pre>
