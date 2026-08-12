#!/usr/bin/env python3
"""Diff Stockpiler local CVE PoCs against Nuclei template CVE coverage.

Usage:
  STOCKPILER_ROOT=/var/lib/stockpiler/data ./scripts/diff-nuclei-cves.py
  ./scripts/diff-nuclei-cves.py --root /path/to/data --templates ~/nuclei-templates
  ./scripts/diff-nuclei-cves.py --clone-templates   # fetch templates if missing
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d+\b")


def resolve_root(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("STOCKPILER_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve().parent.parent
    data = here / "data"
    if data.is_dir():
        return data
    if any(here.glob("CVE-*")):
        return here
    raise SystemExit(
        "No Stockpiler data root. Set STOCKPILER_ROOT or pass --root."
    )


def stockpiler_cves(root: Path) -> set[str]:
    found: set[str] = set()
    for year in root.glob("CVE-*"):
        if not year.is_dir():
            continue
        for cve_dir in year.iterdir():
            if cve_dir.is_dir() and CVE_RE.fullmatch(cve_dir.name):
                found.add(cve_dir.name.upper())
    return found


def extract_cves_from_text(text: str) -> set[str]:
    return {m.group(0).upper() for m in CVE_RE.finditer(text)}


def nuclei_cves(templates_dir: Path) -> set[str]:
    found: set[str] = set()
    # Filenames like CVE-2021-44228.yaml are the common case
    for path in templates_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".yaml", ".yml", ".md", ".json"}:
            # still check filename
            found |= extract_cves_from_text(path.name)
            continue
        found |= extract_cves_from_text(path.name)
        # Light content scan for id/cve tags (skip huge files)
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 200_000:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        # Prefer structured fields when present
        for line in text.splitlines()[:80]:
            if "cve" in line.lower() or line.strip().startswith("id:"):
                found |= extract_cves_from_text(line)
    return found


def ensure_templates(path: Path, clone: bool) -> Path:
    path = path.expanduser()
    if path.is_dir() and any(path.iterdir()):
        return path.resolve()
    if not clone:
        raise SystemExit(
            f"Nuclei templates not found at {path}. "
            "Pass --clone-templates or --templates DIR."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    url = "https://github.com/projectdiscovery/nuclei-templates.git"
    print(f"Cloning {url} -> {path} (shallow) ...", file=sys.stderr)
    subprocess.check_call(
        ["git", "clone", "--depth", "1", url, str(path)],
    )
    return path.resolve()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", help="STOCKPILER_ROOT (CVE-* tree)")
    ap.add_argument(
        "--templates",
        default=os.environ.get(
            "NUCLEI_TEMPLATES",
            str(Path.home() / "nuclei-templates"),
        ),
        help="Path to nuclei-templates checkout",
    )
    ap.add_argument(
        "--clone-templates",
        action="store_true",
        help="git clone nuclei-templates if missing",
    )
    ap.add_argument(
        "--show",
        choices=("summary", "both", "stockpiler-only", "nuclei-only", "all"),
        default="summary",
        help="What to print (default: summary + sample lists)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=40,
        help="Max IDs to print per list section (0 = unlimited)",
    )
    args = ap.parse_args()

    root = resolve_root(args.root)
    templates = ensure_templates(Path(args.templates), args.clone_templates)

    print(f"Stockpiler root : {root}", file=sys.stderr)
    print(f"Nuclei templates: {templates}", file=sys.stderr)

    sp = stockpiler_cves(root)
    nu = nuclei_cves(templates)
    both = sp & nu
    sp_only = sp - nu
    nu_only = nu - sp

    print()
    print("=== Stockpiler × Nuclei CVE coverage ===")
    print(f"Stockpiler CVEs     : {len(sp)}")
    print(f"Nuclei template CVEs: {len(nu)}")
    print(f"In both             : {len(both)}")
    print(f"Stockpiler only     : {len(sp_only)}  (PoC locally, no Nuclei template CVE id found)")
    print(f"Nuclei only         : {len(nu_only)}  (template exists, no local Stockpiler dir)")
    if sp:
        pct = 100.0 * len(both) / len(sp)
        print(f"PoCs with a Nuclei CVE tag: {pct:.1f}%")

    def dump(title: str, items: set[str]) -> None:
        print()
        print(f"--- {title} ({len(items)}) ---")
        ordered = sorted(items)
        if args.limit and len(ordered) > args.limit:
            ordered = ordered[: args.limit]
            print("\n".join(ordered))
            print(f"... ({len(items) - args.limit} more)")
        else:
            print("\n".join(ordered) if ordered else "(none)")

    if args.show in ("summary", "all", "both"):
        dump("In both (sample)", both)
    if args.show in ("summary", "all", "stockpiler-only"):
        dump("Stockpiler only (sample)", sp_only)
    if args.show in ("all", "nuclei-only"):
        dump("Nuclei only (sample)", nu_only)


if __name__ == "__main__":
    main()
