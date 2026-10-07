import base64
import json
import unittest
from unittest.mock import patch

from stockpiler.convert import convert
from stockpiler.store import CandidateRecord


class ConvertTests(unittest.TestCase):
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
