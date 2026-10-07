"""PostgreSQL persistence for validated Stockpile PoCs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .contract import NormalizedPoc, normalize_vulnerability_ids, validate_normalized_poc


@dataclass(frozen=True)
class PocRecord:
    poc_id: str
    vulnerability_ids: tuple[str, ...]
    source_url: str
    source_commit: str
    target_constraints: dict[str, Any]
    source: bytes
    sha256: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: int
    vulnerability_ids: tuple[str, ...]
    source_url: str
    source_commit: str


class StockpileStore:
    def __init__(self, dsn: str, connector: Callable[[str], Any] | None = None) -> None:
        if not dsn.strip():
            raise ValueError("STOCKPILE_DSN is required")
        self.dsn = dsn
        self._connector = connector

    def _connect(self):
        if self._connector is not None:
            return self._connector(self.dsn)
        import psycopg

        return psycopg.connect(self.dsn, connect_timeout=10)

    def put_candidate(self, *, vulnerability_ids: list[str], source_url: str, source_commit: str) -> None:
        identifiers = normalize_vulnerability_ids(vulnerability_ids)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO stockpile_candidates (
                    vulnerability_ids, source_url, source_commit, conversion_status
                ) VALUES (%s, %s, %s, 'pending')
                ON CONFLICT (source_url, source_commit) DO UPDATE SET
                    vulnerability_ids = EXCLUDED.vulnerability_ids
                """,
                (list(identifiers), source_url, source_commit),
            )

    def claim_candidates(
        self, limit: int = 10, stale_after_seconds: int = 900
    ) -> list[CandidateRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("candidate limit must be between 1 and 100")
        if not 1 <= stale_after_seconds <= 86400:
            raise ValueError("claim timeout must be between 1 and 86400 seconds")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH selected AS (
                    SELECT candidate_id
                    FROM stockpile_candidates
                    WHERE conversion_status = 'pending'
                       OR (
                           conversion_status = 'converting'
                           AND (
                               conversion_claimed_at IS NULL
                               OR conversion_claimed_at < CURRENT_TIMESTAMP
                                  - (%s * INTERVAL '1 second')
                           )
                       )
                    ORDER BY discovered_at, candidate_id
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE stockpile_candidates AS candidate
                SET conversion_status = 'converting',
                    conversion_claimed_at = CURRENT_TIMESTAMP,
                    conversion_error = NULL
                FROM selected
                WHERE candidate.candidate_id = selected.candidate_id
                RETURNING candidate.candidate_id, candidate.vulnerability_ids,
                          candidate.source_url, candidate.source_commit
                """,
                (stale_after_seconds, limit),
            )
            rows = cursor.fetchall()
            names = [column.name for column in cursor.description]
        return [
            CandidateRecord(
                candidate_id=int(row["candidate_id"]),
                vulnerability_ids=tuple(row["vulnerability_ids"]),
                source_url=str(row["source_url"]),
                source_commit=str(row["source_commit"]),
            )
            for raw in rows
            for row in [raw if isinstance(raw, dict) else dict(zip(names, raw, strict=True))]
        ]

    def mark_candidate(self, candidate_id: int, status: str, error: str | None = None) -> None:
        if status not in {"pending", "converting", "validated", "rejected"}:
            raise ValueError("invalid conversion status")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE stockpile_candidates
                SET conversion_status = %s,
                    conversion_error = %s,
                    conversion_claimed_at = CASE
                        WHEN %s = 'converting' THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END
                WHERE candidate_id = %s
                """,
                (status, error[:4096] if error else None, status, candidate_id),
            )

    def put(self, poc: NormalizedPoc, *, constraints: dict[str, Any], metadata: dict[str, Any]) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO stockpile_pocs (
                    poc_id, vulnerability_ids, source_url, source_commit,
                    target_constraints, runtime, content, sha256, metadata,
                    conversion_status, enabled
                ) VALUES (%s, %s, %s, %s, %s::jsonb, 'python3', %s, %s, %s::jsonb, 'validated', TRUE)
                ON CONFLICT (poc_id) DO UPDATE SET
                    vulnerability_ids = EXCLUDED.vulnerability_ids,
                    source_url = EXCLUDED.source_url,
                    source_commit = EXCLUDED.source_commit,
                    target_constraints = EXCLUDED.target_constraints,
                    content = EXCLUDED.content,
                    sha256 = EXCLUDED.sha256,
                    metadata = EXCLUDED.metadata,
                    conversion_status = 'validated',
                    enabled = TRUE,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    poc.poc_id,
                    list(poc.vulnerability_ids),
                    poc.source_url,
                    poc.source_commit,
                    json.dumps(constraints),
                    poc.source,
                    poc.sha256,
                    json.dumps(metadata),
                ),
            )

    def lookup(self, vulnerability_id: str, *, target_triple: str | None = None) -> list[PocRecord]:
        vulnerability = normalize_vulnerability_ids([vulnerability_id])[0]
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT poc_id, vulnerability_ids, source_url, source_commit,
                       target_constraints, content, sha256, metadata
                FROM stockpile_pocs
                WHERE %s = ANY(vulnerability_ids)
                  AND conversion_status = 'validated'
                  AND enabled = TRUE
                  AND (%s IS NULL OR target_constraints->>'target_triple' IS NULL
                       OR target_constraints->>'target_triple' = %s)
                ORDER BY updated_at DESC, poc_id ASC
                """,
                (vulnerability, target_triple, target_triple),
            )
            rows = cursor.fetchall()
            names = [column.name for column in cursor.description]
        result: list[PocRecord] = []
        for raw in rows:
            row = raw if isinstance(raw, dict) else dict(zip(names, raw, strict=True))
            source = bytes(row["content"])
            validated = validate_normalized_poc(
                poc_id=str(row["poc_id"]),
                vulnerability_ids=row["vulnerability_ids"],
                source_url=str(row["source_url"]),
                source_commit=str(row["source_commit"]),
                source=source,
            )
            if validated.sha256 != str(row["sha256"]).lower():
                raise ValueError("stored PoC sha256 mismatch")
            constraints = row["target_constraints"]
            metadata = row["metadata"]
            result.append(
                PocRecord(
                    poc_id=validated.poc_id,
                    vulnerability_ids=validated.vulnerability_ids,
                    source_url=validated.source_url,
                    source_commit=validated.source_commit,
                    target_constraints=constraints if isinstance(constraints, dict) else json.loads(constraints),
                    source=source,
                    sha256=validated.sha256,
                    metadata=metadata if isinstance(metadata, dict) else json.loads(metadata),
                )
            )
        return result
