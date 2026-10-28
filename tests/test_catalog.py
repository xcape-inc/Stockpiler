from pathlib import Path
from unittest.mock import patch

import pytest

from catalog import apache_cve_2021_41773 as apache

from stockpiler.contract import validate_normalized_poc


def test_apache_firing_range_item_obeys_normalized_contract():
    source = (Path(__file__).resolve().parents[1] / "catalog" / "apache_cve_2021_41773.py").read_bytes()
    item = validate_normalized_poc(
        poc_id="apache.cve-2021-41773-v1",
        vulnerability_ids=["CVE-2021-41773"],
        source_url="https://github.com/xcape-inc/Stockpiler/blob/1e1e63a7c3a930d9d63cdd7c37f9e86d1718c195/catalog/apache_cve_2021_41773.py",
        source_commit="1e1e63a7c3a930d9d63cdd7c37f9e86d1718c195",
        source=source,
    )
    assert item.sha256 == "83b5a7e6d75ec8b7aa02fd070eca05e5d4d7157ac1a860107379ca238f7e738b"


class FakeConnection:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def sendall(self, _):
        pass

    def recv(self, _):
        return next(self.chunks)


@pytest.mark.parametrize("chunks,message", [
    ([b""], "ended before response headers"),
    ([b"x" * 4096] * 17, "response headers too large"),
])
def test_connect_rejects_incomplete_or_unbounded_headers(chunks, message):
    with patch.object(apache.socket, "create_connection", return_value=FakeConnection(chunks)), \
            patch.dict(apache.os.environ, {"XCAPE_TARGET": "example.test:80", "XCAPE_PROXY_URL": "http://127.0.0.1:8876"}):
        with pytest.raises(RuntimeError, match=message):
            apache.run(b"synthetic")
