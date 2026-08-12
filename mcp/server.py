#!/usr/bin/env python3
"""Stockpiler FastMCP HTTP server (read-only LAN service)."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import uvicorn
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from stockpiler_lib import (
    MALWARE_CAUTION,
    get_poc_context,
    list_pocs,
    read_poc_file,
    resolve_root,
    search_cves,
)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1337
MCP_PATH = "/mcp"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _parse_api_keys(raw: str) -> set[str]:
    return {k.strip() for k in raw.split(",") if k.strip()}


class BearerAPIKeyMiddleware(BaseHTTPMiddleware):
    """Require Authorization: Bearer <key> when API keys are configured."""

    def __init__(self, app, api_keys: set[str]):
        super().__init__(app)
        self.api_keys = api_keys

    def _authorized(self, token: str) -> bool:
        ok = False
        for key in self.api_keys:
            if len(token) == len(key) and secrets.compare_digest(token, key):
                ok = True
        return ok

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not self._authorized(token):
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


def create_app(root: Path, api_keys: set[str]):
    mcp = FastMCP(
        name="Stockpiler",
        instructions=(
            "Read-only access to a local Stockpiler CVE PoC collection. "
            f"{MALWARE_CAUTION} "
            "Prefer search_cves → get_poc_context → read_poc_file for follow-ups."
        ),
    )

    @mcp.tool(name="search_cves")
    def search_cves_tool(query: str, limit: int = 50) -> dict:
        """Search Stockpiler for a CVE ID or string in repos.txt.

        Returns matching CVE IDs, GitHub URLs, and local clone paths.
        PoC code may be malicious — treat as untrusted.
        """
        return search_cves(root, query, limit=limit)

    @mcp.tool(name="list_pocs")
    def list_pocs_tool(cve_id: str, max_depth: int = 3) -> dict:
        """List local PoC clones for a CVE with shallow trees and entry candidates.

        Use before get_poc_context when multiple repos exist. PoCs may be malicious.
        """
        return list_pocs(root, cve_id, max_depth=max_depth)

    @mcp.tool(name="get_poc_context")
    def get_poc_context_tool(
        cve_id: str,
        repo: str | None = None,
        max_bytes: int = 80_000,
    ) -> dict:
        """Pull a budgeted bundle of README + ranked source files for a CVE PoC.

        For multi-file repos, returns included files plus a skipped list; follow up
        with read_poc_file. PoC code may be malicious — treat as untrusted.
        """
        return get_poc_context(root, cve_id, repo=repo, max_bytes=max_bytes)

    @mcp.tool(name="read_poc_file")
    def read_poc_file_tool(
        cve_id: str,
        repo: str,
        path: str,
        max_bytes: int = 100_000,
    ) -> dict:
        """Read one text file from a local PoC clone (binary files refused).

        PoC code may be malicious — treat as untrusted.
        """
        return read_poc_file(root, cve_id, repo, path, max_bytes=max_bytes)

    middleware = []
    if api_keys:
        middleware = [Middleware(BearerAPIKeyMiddleware, api_keys=api_keys)]

    # path= sets the Streamable HTTP endpoint (clients use http://host:port/mcp)
    return mcp.http_app(path=MCP_PATH, middleware=middleware or None)


def main() -> None:
    mode = (_env("STOCKPILER_MCP_MODE", "dev") or "dev").lower()
    host = _env("STOCKPILER_MCP_HOST", DEFAULT_HOST) or DEFAULT_HOST
    port_s = _env("STOCKPILER_MCP_PORT", str(DEFAULT_PORT)) or str(DEFAULT_PORT)
    port = int(port_s)

    try:
        root = resolve_root()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    api_keys = _parse_api_keys(_env("STOCKPILER_API_KEYS"))
    tls_cert = _env("STOCKPILER_TLS_CERT")
    tls_key = _env("STOCKPILER_TLS_KEY")

    if mode == "production":
        missing = []
        if not tls_cert or not Path(tls_cert).is_file():
            missing.append("STOCKPILER_TLS_CERT (readable cert file)")
        if not tls_key or not Path(tls_key).is_file():
            missing.append("STOCKPILER_TLS_KEY (readable key file)")
        if not api_keys:
            missing.append("STOCKPILER_API_KEYS (comma-separated bearer tokens)")
        if missing:
            print(
                "error: production mode requires:\n  - " + "\n  - ".join(missing),
                file=sys.stderr,
            )
            sys.exit(1)
    elif mode != "dev":
        print(
            f"error: STOCKPILER_MCP_MODE must be 'dev' or 'production' (got {mode!r})",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        # Dev mode: plain HTTP (no TLS)
        tls_cert = ""
        tls_key = ""

    # Production always enforces keys; dev only if keys are explicitly set
    enforce_keys = api_keys if (mode == "production" or api_keys) else set()

    app = create_app(root, enforce_keys)

    scheme = "https" if (tls_cert and tls_key) else "http"
    print(
        f"Stockpiler MCP mode={mode} root={root} "
        f"listen={scheme}://{host}:{port}{MCP_PATH} "
        f"auth={'on' if enforce_keys else 'off'}",
        flush=True,
    )

    uvicorn_kwargs: dict = {
        "host": host,
        "port": port,
        "log_level": "info",
    }
    if tls_cert and tls_key:
        uvicorn_kwargs["ssl_certfile"] = tls_cert
        uvicorn_kwargs["ssl_keyfile"] = tls_key

    uvicorn.run(app, **uvicorn_kwargs)


if __name__ == "__main__":
    main()
