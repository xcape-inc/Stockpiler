import unittest
from unittest.mock import MagicMock

from stockpiler.store import StockpileStore


class StoreTests(unittest.TestCase):
    def test_claim_candidates_updates_status_in_locked_statement(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        cursor.description = []
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        connection = MagicMock()
        connection.cursor.return_value = cursor_context
        connection_context = MagicMock()
        connection_context.__enter__.return_value = connection
        connector = MagicMock(return_value=connection_context)

        store = StockpileStore("postgresql://test", connector=connector)
        self.assertEqual(store.claim_candidates(4, 120), [])

        statement, parameters = cursor.execute.call_args.args
        normalized = " ".join(statement.split()).upper()
        self.assertIn("FOR UPDATE SKIP LOCKED", normalized)
        self.assertIn("UPDATE STOCKPILE_CANDIDATES", normalized)
        self.assertIn("RETURNING CANDIDATE.CANDIDATE_ID", normalized)
        self.assertEqual(parameters, (120, 4))


if __name__ == "__main__":
    unittest.main()

