"""Local Stockpiler collection behavior. Fixtures stay on disk and are never executed."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

import stockpiler_lib


def load_diff():
    path = Path(__file__).resolve().parents[1] / "scripts" / "diff-nuclei-cves.py"
    spec = importlib.util.spec_from_file_location("diff_nuclei_cves", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def collection(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    repo = root / "CVE-2021" / "CVE-2021-41773" / "0" / "apache-poc"
    repo.mkdir(parents=True)
    (repo.parent.parent / "repos.txt").write_text("https://example.invalid/org/apache-poc\n", encoding="utf-8")
    (repo / "README.md").write_text("# fixture\n", encoding="utf-8")
    (repo / "poc.py").write_text("value = 1\n", encoding="utf-8")
    (repo / "payload.bin").write_bytes(b"\x00\x01")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (repo / "escape.py").symlink_to(outside)
    return root


def test_normalize_cve_id_rejects_unexpected_text():
    assert stockpiler_lib.normalize_cve_id(" cve-2021-41773 ") == "CVE-2021-41773"
    with pytest.raises(ValueError):
        stockpiler_lib.normalize_cve_id("CVE-2021-41773; rm")


def test_safe_join_rejects_path_escape(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(PermissionError):
        stockpiler_lib.safe_join(root, "..", "outside")


def test_resolve_root_uses_explicit_directory(tmp_path: Path):
    target = tmp_path / "new-root"
    assert stockpiler_lib.resolve_root(str(target)) == target.resolve()
    assert target.is_dir()


def test_resolve_root_rejects_missing_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    missing = tmp_path / "missing"
    monkeypatch.setenv("STOCKPILER_ROOT", str(missing))
    with pytest.raises(FileNotFoundError):
        stockpiler_lib.resolve_root()


def test_search_empty_query_returns_no_matches(tmp_path: Path):
    result = stockpiler_lib.search_cves(collection(tmp_path), "  ")
    assert result["matches"] == []
    assert "untrusted" in result["caution"]


def test_search_exact_cve_returns_urls_and_clone(tmp_path: Path):
    result = stockpiler_lib.search_cves(collection(tmp_path), "CVE-2021-41773")
    assert result["count"] == 1
    match = result["matches"][0]
    assert match["urls"] == ["https://example.invalid/org/apache-poc"]
    assert match["local_clones"][0]["repo"] == "apache-poc"


def test_search_missing_cve_reports_no_collection(tmp_path: Path):
    result = stockpiler_lib.search_cves(collection(tmp_path), "CVE-1999-0001")
    assert result["count"] == 0
    assert "No local collection" in result["error"]


def test_search_matches_repository_url_text(tmp_path: Path):
    result = stockpiler_lib.search_cves(collection(tmp_path), "example.invalid")
    assert [item["cve_id"] for item in result["matches"]] == ["CVE-2021-41773"]


def test_list_pocs_ranks_readme_and_skips_symlink(tmp_path: Path):
    listed = stockpiler_lib.list_pocs(collection(tmp_path), "CVE-2021-41773")
    assert listed["found"] is True
    candidates = listed["pocs"][0]["entry_candidates"]
    assert candidates[0]["path"] == "README.md"
    assert "escape.py" not in {item["path"] for item in candidates}


def test_context_reads_source_and_refuses_symlink_and_binary(tmp_path: Path):
    context = stockpiler_lib.get_poc_context(collection(tmp_path), "CVE-2021-41773")
    included = {item["path"]: item["content"] for item in context["included"]}
    assert included["poc.py"] == "value = 1\n"
    assert "secret" not in "\n".join(included.values())
    skipped = {item["path"]: item["reason"] for item in context["skipped"]}
    assert "symlink" in skipped["escape.py"]
    assert skipped["payload.bin"] == "binary or non-text"


def test_read_poc_file_rejects_escape_and_binary(tmp_path: Path):
    root = collection(tmp_path)
    text = stockpiler_lib.read_poc_file(root, "CVE-2021-41773", "apache-poc", "poc.py")
    assert text["content"] == "value = 1\n"
    with pytest.raises(PermissionError):
        stockpiler_lib.read_poc_file(root, "CVE-2021-41773", "apache-poc", "../repos.txt")
    with pytest.raises(PermissionError):
        stockpiler_lib.read_poc_file(root, "CVE-2021-41773", "apache-poc", "escape.py")
    binary = stockpiler_lib.read_poc_file(root, "CVE-2021-41773", "apache-poc", "payload.bin")
    assert binary["error"] == "Refusing to read binary/non-text file"


def test_nuclei_diff_compares_local_ids_without_cloning(tmp_path: Path):
    diff = load_diff()
    root = collection(tmp_path)
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "CVE-2021-41773.yaml").write_text("id: CVE-2021-41773\ninfo: CVE-2020-1234\n", encoding="utf-8")
    (templates / "notes.md").write_text("unrelated\n", encoding="utf-8")
    assert diff.stockpiler_cves(root) == {"CVE-2021-41773"}
    assert diff.extract_cves_from_text("id: CVE-2021-41773\ninfo: CVE-2020-1234\n") == {
        "CVE-2021-41773",
        "CVE-2020-1234",
    }
    assert diff.nuclei_cves(templates) == {"CVE-2021-41773", "CVE-2020-1234"}
    with pytest.raises(SystemExit):
        diff.ensure_templates(tmp_path / "missing-templates", clone=False)
