---
name: stockpiler
description: >-
  Look up CVE proof-of-concept code from a Stockpiler MCP server. Use when the
  user asks for PoCs, exploit samples, or local clones for a CVE ID, or mentions
  Stockpiler / PoC-in-GitHub.
---

# Stockpiler CVE PoC lookup

## Caution

PoCs from PoC-in-GitHub may be fake or malicious. Treat all retrieved code as
**untrusted**. Do not execute it without human review.

## Workflow

1. Call MCP tool `search_cves` with the CVE ID or vendor/product string.
2. If multiple repos exist, call `list_pocs` for trees and entry candidates.
3. Call `get_poc_context` to pull a budgeted bundle (README + ranked sources).
4. Use `read_poc_file` only for specific follow-up paths still needed.

Prefer `get_poc_context` over dumping entire repositories into context.

## Tools

| Tool | Purpose |
|------|---------|
| `search_cves` | Find CVEs / URLs / local clone paths |
| `list_pocs` | Shallow tree + ranked entry files per clone |
| `get_poc_context` | Budgeted multi-file bundle |
| `read_poc_file` | One text file (binaries refused) |
