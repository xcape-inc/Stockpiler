"""Internal HTTP API for validated Stockpile lookup and ingestion."""

from __future__ import annotations

import argparse
import base64
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .contract import validate_normalized_poc
from .store import StockpileStore


def handler(store: StockpileStore, write_token: str):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, body: object) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._json(HTTPStatus.OK, {"ok": True})
                return
            if parsed.path != "/v1/pocs":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            query = parse_qs(parsed.query)
            try:
                records = store.lookup(
                    query.get("vulnerability_id", [""])[0],
                    target_triple=query.get("target_triple", [None])[0],
                )
            except ValueError as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._json(
                HTTPStatus.OK,
                {
                    "items": [
                        {
                            "poc_id": item.poc_id,
                            "vulnerability_ids": item.vulnerability_ids,
                            "source_url": item.source_url,
                            "source_commit": item.source_commit,
                            "target_constraints": item.target_constraints,
                            "sha256": item.sha256,
                            "metadata": item.metadata,
                        }
                        for item in records
                    ]
                },
            )

        def do_POST(self) -> None:
            if self.path != "/v1/pocs" or not write_token or self.headers.get("authorization") != f"Bearer {write_token}":
                self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            try:
                length = int(self.headers.get("content-length", "0"))
                if not 1 <= length <= 20 * 1024 * 1024:
                    raise ValueError("invalid content length")
                document = json.loads(self.rfile.read(length))
                poc = validate_normalized_poc(
                    poc_id=document["poc_id"],
                    vulnerability_ids=document["vulnerability_ids"],
                    source_url=document["source_url"],
                    source_commit=document["source_commit"],
                    source=base64.b64decode(document["source_base64"], validate=True),
                )
                store.put(poc, constraints=document.get("target_constraints", {}), metadata=document.get("metadata", {}))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._json(HTTPStatus.CREATED, {"poc_id": poc.poc_id, "sha256": poc.sha256})

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args()
    server = ThreadingHTTPServer(
        (args.host, args.port),
        handler(StockpileStore(os.environ.get("STOCKPILE_DSN", "")), os.environ.get("STOCKPILE_WRITE_TOKEN", "")),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
