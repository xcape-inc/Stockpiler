import base64
import json
import unittest
from unittest.mock import MagicMock, patch

from stockpiler.convert import convert, run_once
from stockpiler.store import CandidateRecord


class ConvertTests(unittest.TestCase):
    def test_empty_command_fails_before_claiming(self):
        store = MagicMock()
        with self.assertRaisesRegex(ValueError, "STOCKPILER_CONVERTER_COMMAND is required"):
            run_once(store, "  ")
        store.claim_candidates.assert_not_called()

    def test_missing_executable_fails_before_claiming(self):
        store = MagicMock()
        with patch("stockpiler.convert.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "executable not found"):
                run_once(store, "unavailable-converter --json")
        store.claim_candidates.assert_not_called()

    def test_serial_batch_claims_one_candidate_at_a_time(self):
        store = MagicMock()
        first = CandidateRecord(1, ("CVE-2026-1001",), "https://github.com/example/one", "a" * 40, "first")
        second = CandidateRecord(2, ("CVE-2026-1002",), "https://github.com/example/two", "b" * 40, "second")
        store.claim_candidates.side_effect = [[first], [second]]
        store.publish_claimed.return_value = True
        with patch("stockpiler.convert.shutil.which", return_value="/usr/bin/converter"), patch("stockpiler.convert.convert", return_value=(object(), {}, {})):
            self.assertEqual(run_once(store, "converter", limit=2), {"validated": 2, "rejected": 0})
        self.assertEqual([call.args[0] for call in store.claim_candidates.call_args_list], [1, 1])
        self.assertEqual(store.publish_claimed.call_count, 2)

    def test_converter_output_must_implement_single_payload_contract(self):
        candidate = CandidateRecord(1, ("CVE-2026-1001",), "https://github.com/xcape-inc/fixture", "a" * 40)
        output = json.dumps({
            "poc_id": "fixture-v1",
            "source_base64": base64.b64encode(b"def run(payload):\n    return len(payload)\n").decode(),
            "target_constraints": {"target_triple": "aarch64-linux-gnu"},
        })
        with patch("stockpiler.convert.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = output
            run.return_value.stderr = ""
            poc, constraints, _metadata = convert(candidate, "converter --json")
        self.assertEqual(poc.vulnerability_ids, ("CVE-2026-1001",))
        self.assertEqual(constraints["target_triple"], "aarch64-linux-gnu")


if __name__ == "__main__":
    unittest.main()
