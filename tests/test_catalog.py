from pathlib import Path

from stockpiler.contract import validate_normalized_poc


def test_apache_firing_range_item_obeys_normalized_contract():
    source = (Path(__file__).resolve().parents[1] / "catalog" / "apache_cve_2021_41773.py").read_bytes()
    item = validate_normalized_poc(
        poc_id="apache.cve-2021-41773-v1",
        vulnerability_ids=["CVE-2021-41773"],
        source_url="https://github.com/xcape-inc/Stockpiler/blob/19e143f344731a701153eda12d68ccd38a0d2dd6/catalog/apache_cve_2021_41773.py",
        source_commit="19e143f344731a701153eda12d68ccd38a0d2dd6",
        source=source,
    )
    assert item.sha256 == "6918c0214970165d7c039b747474566aa99e17b9cf20501fdbf893270285b7f1"
