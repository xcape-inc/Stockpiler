import os
import threading
import unittest
import uuid
from pathlib import Path

from stockpiler.contract import validate_normalized_poc
from stockpiler.convert import run_once
from stockpiler.store import StockpileStore


@unittest.skipUnless(os.getenv("STOCKPILE_TEST_DSN"), "STOCKPILE_TEST_DSN not configured")
class PostgresClaimTests(unittest.TestCase):
    def test_empty_converter_command_keeps_candidate_pending(self):
        import psycopg

        dsn = os.environ["STOCKPILE_TEST_DSN"]
        schema = (Path(__file__).parents[1] / "stockpiler" / "schema.sql").read_text()
        source_url = f"https://github.com/stockpiler-test/{uuid.uuid4()}"
        with psycopg.connect(dsn) as connection:
            connection.execute(schema)
            connection.execute(
                """
                INSERT INTO stockpile_candidates
                    (vulnerability_ids, source_url, source_commit)
                VALUES (%s, %s, %s)
                """,
                (["CVE-2026-1001"], source_url, "a" * 40),
            )
        try:
            with self.assertRaisesRegex(ValueError, "STOCKPILER_CONVERTER_COMMAND is required"):
                run_once(StockpileStore(dsn), "")
            with psycopg.connect(dsn) as connection:
                state = connection.execute(
                    """
                    SELECT conversion_status, conversion_claimed_at, conversion_claim_token
                    FROM stockpile_candidates WHERE source_url = %s
                    """,
                    (source_url,),
                ).fetchone()
            self.assertEqual(state, ("pending", None, None))
        finally:
            with psycopg.connect(dsn) as connection:
                connection.execute("DELETE FROM stockpile_candidates WHERE source_url = %s", (source_url,))

    def test_reclaimed_worker_cannot_publish_or_finish_old_claim(self):
        import psycopg

        dsn = os.environ["STOCKPILE_TEST_DSN"]
        schema = (Path(__file__).parents[1] / "stockpiler" / "schema.sql").read_text()
        source_url = f"https://github.com/stockpiler-test/{uuid.uuid4()}"
        store = StockpileStore(dsn)
        with psycopg.connect(dsn) as connection:
            connection.execute(schema)
            connection.execute(
                """
                INSERT INTO stockpile_candidates
                    (vulnerability_ids, source_url, source_commit)
                VALUES (%s, %s, %s)
                """,
                (["CVE-2026-1001"], source_url, "a" * 40),
            )

        try:
            old = next(candidate for candidate in store.claim_candidates(1) if candidate.source_url == source_url)
            with psycopg.connect(dsn) as connection:
                connection.execute(
                    """
                    UPDATE stockpile_candidates
                    SET conversion_claimed_at = CURRENT_TIMESTAMP - INTERVAL '901 seconds'
                    WHERE candidate_id = %s
                    """,
                    (old.candidate_id,),
                )
            new = next(candidate for candidate in store.claim_candidates(1) if candidate.source_url == source_url)
            self.assertNotEqual(old.claim_token, new.claim_token)
            poc = validate_normalized_poc(
                poc_id=f"test-{uuid.uuid4()}",
                vulnerability_ids=old.vulnerability_ids,
                source_url=old.source_url,
                source_commit=old.source_commit,
                source=b"def run(payload):\n    return len(payload)\n",
            )
            self.assertFalse(store.publish_claimed(old, poc, constraints={}, metadata={}))
            self.assertFalse(store.mark_candidate(old.candidate_id, old.claim_token, "rejected", "late"))
            self.assertTrue(store.publish_claimed(new, poc, constraints={}, metadata={}))
            with psycopg.connect(dsn) as connection:
                status, token = connection.execute(
                    "SELECT conversion_status, conversion_claim_token FROM stockpile_candidates WHERE candidate_id = %s",
                    (old.candidate_id,),
                ).fetchone()
                published = connection.execute(
                    "SELECT count(*) FROM stockpile_pocs WHERE poc_id = %s", (poc.poc_id,)
                ).fetchone()[0]
            self.assertEqual((status, token, published), ("validated", None, 1))
        finally:
            with psycopg.connect(dsn) as connection:
                connection.execute("DELETE FROM stockpile_candidates WHERE source_url = %s", (source_url,))
                if "poc" in locals():
                    connection.execute("DELETE FROM stockpile_pocs WHERE poc_id = %s", (poc.poc_id,))

    def test_concurrent_workers_claim_candidate_once(self):
        import psycopg

        dsn = os.environ["STOCKPILE_TEST_DSN"]
        schema = (Path(__file__).parents[1] / "stockpiler" / "schema.sql").read_text()
        source_url = f"https://example.invalid/{uuid.uuid4()}"
        with psycopg.connect(dsn) as connection:
            connection.execute(schema)
            connection.execute(
                """
                INSERT INTO stockpile_candidates
                    (vulnerability_ids, source_url, source_commit)
                VALUES (%s, %s, %s)
                """,
                (["CVE-2026-1001"], source_url, "a" * 40),
            )

        barrier = threading.Barrier(2)
        claims = []
        errors = []

        def claim() -> None:
            try:
                barrier.wait()
                claims.append(StockpileStore(dsn).claim_candidates(1))
            except Exception as error:
                errors.append(error)

        workers = [threading.Thread(target=claim) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual(errors, [])
        claimed_ids = [item.candidate_id for batch in claims for item in batch]
        self.assertEqual(len(claimed_ids), 1)
        with psycopg.connect(dsn) as connection:
            status = connection.execute(
                "SELECT conversion_status FROM stockpile_candidates WHERE source_url = %s",
                (source_url,),
            ).fetchone()[0]
            connection.execute(
                "DELETE FROM stockpile_candidates WHERE source_url = %s", (source_url,)
            )
        self.assertEqual(status, "converting")


if __name__ == "__main__":
    unittest.main()
