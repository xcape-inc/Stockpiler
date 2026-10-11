"""Run configured PoC normalizer and admit only validated run(payload) output."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import subprocess

from .contract import validate_normalized_poc
from .store import CandidateRecord, StockpileStore


def converter_arguments(command: str) -> list[str]:
    arguments = shlex.split(command)
    if not arguments:
        raise ValueError("STOCKPILER_CONVERTER_COMMAND is required")
    return arguments


def convert(candidate: CandidateRecord, command: str, timeout: int = 600):
    arguments = converter_arguments(command)
    request = json.dumps(
        {
            "vulnerability_ids": candidate.vulnerability_ids,
            "source_url": candidate.source_url,
            "source_commit": candidate.source_commit,
            "contract": "Python source defining exactly run(payload)",
        }
    )
    completed = subprocess.run(
        arguments,
        input=request,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={"PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin")},
    )
    if completed.returncode != 0:
        raise ValueError(f"converter failed with exit code {completed.returncode}: {completed.stderr[-2048:]}")
    try:
        result = json.loads(completed.stdout)
        source = base64.b64decode(result["source_base64"], validate=True)
        poc = validate_normalized_poc(
            poc_id=result["poc_id"],
            vulnerability_ids=candidate.vulnerability_ids,
            source_url=candidate.source_url,
            source_commit=candidate.source_commit,
            source=source,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid converter output: {error}") from error
    return poc, result.get("target_constraints", {}), result.get("metadata", {})


def run_once(
    store: StockpileStore,
    command: str,
    limit: int = 10,
    stale_after_seconds: int = 900,
) -> dict[str, int]:
    converter_arguments(command)
    counts = {"validated": 0, "rejected": 0}
    if not 1 <= limit <= 100:
        raise ValueError("candidate limit must be between 1 and 100")
    for _ in range(limit):
        # Claim just before conversion so later rows cannot expire while queued.
        claimed = store.claim_candidates(1, stale_after_seconds)
        if not claimed:
            break
        candidate = claimed[0]
        try:
            poc, constraints, metadata = convert(candidate, command)
            if store.publish_claimed(candidate, poc, constraints=constraints, metadata=metadata):
                counts["validated"] += 1
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            if store.mark_candidate(candidate.candidate_id, candidate.claim_token, "rejected", str(error)):
                counts["rejected"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    result = run_once(
        StockpileStore(os.environ.get("STOCKPILE_DSN", "")),
        os.environ.get("STOCKPILER_CONVERTER_COMMAND", ""),
        args.limit,
        int(os.environ.get("STOCKPILER_CLAIM_TIMEOUT_SECONDS", "900")),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
