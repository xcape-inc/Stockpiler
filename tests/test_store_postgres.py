import os
import threading
import unittest
import uuid
from pathlib import Path

from stockpiler.store import StockpileStore


@unittest.skipUnless(os.getenv("STOCKPILE_TEST_DSN"), "STOCKPILE_TEST_DSN not configured")
class PostgresClaimTests(unittest.TestCase):
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

        def claim() -> None:
            barrier.wait()
            claims.append(StockpileStore(dsn).claim_candidates(1))

        workers = [threading.Thread(target=claim) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

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
