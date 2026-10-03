"""Continuously project Stockpiler's local GitHub cache into DB candidates."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .store import StockpileStore

CVE_DIR = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


@dataclass(frozen=True)
class Candidate:
    vulnerability_ids: tuple[str, ...]
    source_url: str
    source_commit: str


def candidates(root: Path) -> list[Candidate]:
    found: list[Candidate] = []
    for cve_dir in sorted(root.glob("CVE-*/CVE-*")):
        if not cve_dir.is_dir() or not CVE_DIR.fullmatch(cve_dir.name):
            continue
        for slot in sorted(cve_dir.iterdir()):
            if not slot.is_dir():
                continue
            for repository in sorted(slot.iterdir()):
                if not (repository / ".git").is_dir():
                    continue
                try:
                    source_url = subprocess.run(
                        ["git", "-C", str(repository), "remote", "get-url", "origin"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout.strip()
                    source_commit = subprocess.run(
                        ["git", "-C", str(repository), "rev-parse", "HEAD"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout.strip()
                except (OSError, subprocess.SubprocessError):
                    continue
                if source_url.startswith("git@github.com:"):
                    source_url = "https://github.com/" + source_url.removeprefix("git@github.com:")
                source_url = source_url.removesuffix(".git")
                if source_url.startswith("https://github.com/") and re.fullmatch(r"[0-9a-f]{40}", source_commit):
                    found.append(Candidate((cve_dir.name.upper(),), source_url, source_commit))
    return found


def run_once(root: Path, store: StockpileStore) -> int:
    records = candidates(root)
    for record in records:
        store.put_candidate(
            vulnerability_ids=list(record.vulnerability_ids),
            source_url=record.source_url,
            source_commit=record.source_commit,
        )
    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=os.environ.get("STOCKPILER_ROOT", "./data"))
    parser.add_argument("--interval", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 60 <= args.interval <= 86400:
        raise ValueError("interval must be between 60 and 86400 seconds")
    store = StockpileStore(os.environ.get("STOCKPILE_DSN", ""))
    while True:
        count = run_once(Path(args.root), store)
        print(f"projected {count} Stockpile candidates", flush=True)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
