import unittest

from stockpiler.contract import validate_normalized_poc


SOURCE = b"def run(payload):\n    return {'size': len(payload)}\n"


class ContractTests(unittest.TestCase):
    def test_accepts_single_payload_contract_and_both_identifier_types(self):
        result = validate_normalized_poc(
            poc_id="fixture.health-v1",
            vulnerability_ids=["CVE-2026-1001", "EUVD-2026-2001"],
            source_url="https://github.com/xcape-inc/fixture",
            source_commit="a" * 40,
            source=SOURCE,
        )
        self.assertEqual(result.vulnerability_ids, ("CVE-2026-1001", "EUVD-2026-2001"))

    def test_rejects_more_than_one_payload_argument(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            validate_normalized_poc(
                poc_id="fixture.bad",
                vulnerability_ids=["CVE-2026-1001"],
                source_url="https://github.com/xcape-inc/fixture",
                source_commit="a" * 40,
                source=b"def run(payload, target):\n    pass\n",
            )


if __name__ == "__main__":
    unittest.main()
