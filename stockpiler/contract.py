"""Validation contract for normalized Stockpile PoCs."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

VULNERABILITY_ID = re.compile(r"^(?:CVE|EUVD)-\d{4}-\d{1,12}$", re.IGNORECASE)
POC_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_SOURCE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class NormalizedPoc:
    poc_id: str
    vulnerability_ids: tuple[str, ...]
    source_url: str
    source_commit: str
    source: bytes
    sha256: str


def normalize_vulnerability_ids(values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(dict.fromkeys(value.strip().upper() for value in values))
    if not result or len(result) > 64:
        raise ValueError("vulnerability_ids must contain 1 to 64 values")
    if any(not VULNERABILITY_ID.fullmatch(value) for value in result):
        raise ValueError("vulnerability_ids must use CVE-YYYY-N or EUVD-YYYY-N")
    return result


def validate_normalized_poc(
    *,
    poc_id: str,
    vulnerability_ids: Iterable[str],
    source_url: str,
    source_commit: str,
    source: bytes,
) -> NormalizedPoc:
    normalized_id = poc_id.strip().lower()
    if not POC_ID.fullmatch(normalized_id):
        raise ValueError("invalid poc_id")
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise ValueError(f"source size must be between 1 and {MAX_SOURCE_BYTES} bytes")
    if not source_url.startswith("https://github.com/"):
        raise ValueError("source_url must be an HTTPS GitHub URL")
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", source_commit.strip()):
        raise ValueError("source_commit must be a Git commit hash")
    try:
        tree = ast.parse(source.decode("utf-8"), filename=f"{normalized_id}.py")
    except (UnicodeDecodeError, SyntaxError) as error:
        raise ValueError("normalized PoC must be valid UTF-8 Python") from error
    candidates = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run"
    ]
    if len(candidates) != 1 or isinstance(candidates[0], ast.AsyncFunctionDef):
        raise ValueError("normalized PoC must define exactly one synchronous run(payload)")
    args = candidates[0].args
    if (
        len(args.posonlyargs) + len(args.args) != 1
        or args.vararg is not None
        or args.kwarg is not None
        or args.kwonlyargs
        or args.defaults
    ):
        raise ValueError("run must accept exactly one required payload argument")
    return NormalizedPoc(
        poc_id=normalized_id,
        vulnerability_ids=normalize_vulnerability_ids(vulnerability_ids),
        source_url=source_url,
        source_commit=source_commit.lower(),
        source=source,
        sha256=hashlib.sha256(source).hexdigest(),
    )
