"""Stockpiler dataset helpers: search, list, pack, and read under STOCKPILER_ROOT."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

SKIP_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    "node_modules",
    ".tox",
    ".venv",
    "venv",
}

SOURCE_EXTS = {
    ".py",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".go",
    ".rs",
    ".rb",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".bash",
    ".ps1",
    ".java",
    ".kt",
    ".php",
    ".pl",
    ".pm",
    ".lua",
    ".nim",
    ".zig",
    ".cs",
    ".swift",
}

BINARY_EXTS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".a",
    ".bin",
    ".pcap",
    ".pcapng",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".tar",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".wav",
    ".class",
    ".pyc",
    ".pyo",
    ".whl",
    ".egg",
}

ENTRY_NAME_RE = re.compile(
    r"(?i)(^readme(\.|$))|(^poc)|(^exploit)|(^main(\.|$))|(^cve-)|exploit|poc"
)

CVE_ID_RE = re.compile(r"(?i)^CVE-\d{4}-\d+$")

MALWARE_CAUTION = (
    "WARNING: PoCs from PoC-in-GitHub may be fake, malicious, or unsafe. "
    "Treat all code as untrusted; do not execute without review."
)


def resolve_root(explicit: str | None = None) -> Path:
    """Resolve STOCKPILER_ROOT with the same rules as stockpiler.sh."""
    if explicit:
        root = Path(explicit).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    env = os.environ.get("STOCKPILER_ROOT", "").strip()
    if env:
        root = Path(env).expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"STOCKPILER_ROOT does not exist: {root}")
        return root

    # mcp/ is inside the repo; parent is repo root
    repo = Path(__file__).resolve().parent.parent
    data = repo / "data"
    if data.is_dir():
        return data.resolve()

    has_legacy = any(repo.glob("CVE-*")) or (repo / "PoC-in-GitHub").is_dir()
    if has_legacy:
        return repo.resolve()

    raise FileNotFoundError(
        "No Stockpiler data root found. Set STOCKPILER_ROOT or create "
        f"{data} / run stockpiler.sh update."
    )


def normalize_cve_id(cve_id: str) -> str:
    cve = cve_id.strip().upper()
    if not CVE_ID_RE.match(cve):
        raise ValueError(f"Invalid CVE id: {cve_id!r} (expected CVE-YYYY-NNNNN)")
    return cve


def cve_year_dir(root: Path, cve_id: str) -> Path:
    cve = normalize_cve_id(cve_id)
    year = cve.split("-")[1]
    path = root / f"CVE-{year}" / cve
    return path


def safe_join(root: Path, *parts: str) -> Path:
    """Join under root; reject path escape."""
    candidate = (root.joinpath(*parts)).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise PermissionError(f"Path escapes STOCKPILER_ROOT: {candidate}") from exc
    return candidate


def _is_probably_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    return False


def _read_text_capped(path: Path, max_bytes: int) -> tuple[str, bool]:
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    # Decode leniently for source dumps
    text = data.decode("utf-8", errors="replace")
    return text, truncated


def _score_entry(path: Path, repo_root: Path) -> int:
    rel = path.relative_to(repo_root)
    name = path.name
    score = 0
    lower = name.lower()
    if lower.startswith("readme"):
        score += 100
    if ENTRY_NAME_RE.search(name):
        score += 50
    if path.suffix.lower() in SOURCE_EXTS:
        score += 20
    # Prefer shallower files
    score += max(0, 10 - len(rel.parts))
    if path.parent == repo_root:
        score += 15
    return score


def _iter_repo_files(repo_root: Path, max_depth: int = 3):
    root = repo_root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
        # Prune
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIR_NAMES and not d.startswith(".")
        ]
        if depth >= max_depth:
            dirnames[:] = []
            continue
        for name in filenames:
            if name.startswith(".") and not name.lower().startswith("readme"):
                continue
            yield Path(dirpath) / name


def _shallow_tree(repo_root: Path, max_depth: int = 3, max_entries: int = 200) -> list[str]:
    lines: list[str] = []
    root = repo_root.resolve()
    for path in sorted(_iter_repo_files(repo_root, max_depth=max_depth)):
        rel = path.relative_to(root).as_posix()
        lines.append(rel)
        if len(lines) >= max_entries:
            lines.append("… (truncated)")
            break
    return lines


def _local_clones(cve_dir: Path, root: Path | None = None) -> list[dict[str, Any]]:
    clones: list[dict[str, Any]] = []
    if not cve_dir.is_dir():
        return clones

    urls_by_name: dict[str, str] = {}
    repos_txt = cve_dir / "repos.txt"
    if repos_txt.is_file():
        for line in repos_txt.read_text(errors="replace").splitlines():
            url = line.strip()
            if not url:
                continue
            name = url.rstrip("/").split("/")[-1]
            urls_by_name[name] = url

    base = root.resolve() if root is not None else None
    for slot in sorted(cve_dir.iterdir()):
        if not slot.is_dir():
            continue
        for child in sorted(slot.iterdir()):
            if not child.is_dir():
                continue
            reponame = child.name
            if base is not None:
                try:
                    rel = str(child.resolve().relative_to(base))
                except ValueError:
                    rel = str(child)
            else:
                rel = str(child)
            clones.append(
                {
                    "slot": slot.name,
                    "repo": reponame,
                    "path": rel,
                    "url": urls_by_name.get(reponame, ""),
                }
            )
    return clones


def _trim_match(
    entry: dict[str, Any],
    max_urls: int = 50,
    max_clones: int = 25,
) -> dict[str, Any]:
    """Cap large CVE payloads so MCP clients are not flooded."""
    urls = entry.get("urls") or []
    clones = entry.get("local_clones") or []
    out = dict(entry)
    out["url_count"] = len(urls)
    out["clone_count"] = len(clones)
    out["urls"] = urls[:max_urls]
    out["local_clones"] = clones[:max_clones]
    if len(urls) > max_urls or len(clones) > max_clones:
        out["truncated"] = True
    return out


def search_cves(root: Path, query: str, limit: int = 50) -> dict[str, Any]:
    q = query.strip()
    if not q:
        return {"caution": MALWARE_CAUTION, "query": q, "matches": []}

    matches: dict[str, dict[str, Any]] = {}

    # Exact CVE id → direct lookup
    try:
        cve = normalize_cve_id(q)
        cve_dir = cve_year_dir(root, cve)
        if cve_dir.is_dir():
            urls: list[str] = []
            repos_txt = cve_dir / "repos.txt"
            if repos_txt.is_file():
                urls = [
                    ln.strip()
                    for ln in repos_txt.read_text(errors="replace").splitlines()
                    if ln.strip()
                ]
            matches[cve] = _trim_match(
                {
                    "cve_id": cve,
                    "year_dir": cve_dir.parent.name,
                    "urls": urls,
                    "local_clones": _local_clones(cve_dir, root),
                }
            )
            items = list(matches.values())
            return {
                "caution": MALWARE_CAUTION,
                "query": q,
                "count": len(items),
                "matches": items,
            }
        return {
            "caution": MALWARE_CAUTION,
            "query": q,
            "count": 0,
            "matches": [],
            "error": f"No local collection for {cve}",
        }
    except ValueError:
        pass

    pattern = re.compile(re.escape(q), re.IGNORECASE)
    for repos_txt in root.glob("CVE-*/CVE-*/repos.txt"):
        try:
            text = repos_txt.read_text(errors="replace")
        except OSError:
            continue
        cve_id = repos_txt.parent.name
        if not (pattern.search(text) or pattern.search(cve_id)):
            continue

        year_dir = repos_txt.parent.parent.name
        urls = [ln.strip() for ln in text.splitlines() if ln.strip()]
        entry = matches.setdefault(
            cve_id,
            {
                "cve_id": cve_id,
                "year_dir": year_dir,
                "urls": [],
                "local_clones": [],
            },
        )
        for url in urls:
            if url not in entry["urls"]:
                entry["urls"].append(url)
        for clone in _local_clones(repos_txt.parent, root):
            if clone not in entry["local_clones"]:
                entry["local_clones"].append(clone)

    items = [
        _trim_match(m) for m in sorted(matches.values(), key=lambda m: m["cve_id"])[:limit]
    ]
    return {
        "caution": MALWARE_CAUTION,
        "query": q,
        "count": len(items),
        "matches": items,
    }


def list_pocs(root: Path, cve_id: str, max_depth: int = 3) -> dict[str, Any]:
    cve = normalize_cve_id(cve_id)
    cve_dir = cve_year_dir(root, cve)
    if not cve_dir.is_dir():
        return {
            "caution": MALWARE_CAUTION,
            "cve_id": cve,
            "found": False,
            "error": f"No local collection for {cve}",
            "pocs": [],
        }

    urls: list[str] = []
    repos_txt = cve_dir / "repos.txt"
    if repos_txt.is_file():
        urls = [
            ln.strip()
            for ln in repos_txt.read_text(errors="replace").splitlines()
            if ln.strip()
        ]

    pocs = []
    for clone in _local_clones(cve_dir, root):
        repo_path = (root / clone["path"]).resolve()
        files = list(_iter_repo_files(repo_path, max_depth=max_depth))
        ranked = sorted(files, key=lambda p: _score_entry(p, repo_path), reverse=True)
        candidates = [
            {
                "path": p.relative_to(repo_path).as_posix(),
                "score": _score_entry(p, repo_path),
                "bytes": p.stat().st_size if p.is_file() else 0,
            }
            for p in ranked[:15]
        ]
        pocs.append(
            {
                **clone,
                "file_count": len(files),
                "tree": _shallow_tree(repo_path, max_depth=max_depth),
                "entry_candidates": candidates,
            }
        )

    try:
        cve_rel = str(cve_dir.resolve().relative_to(root.resolve()))
    except ValueError:
        cve_rel = str(cve_dir)

    return {
        "caution": MALWARE_CAUTION,
        "cve_id": cve,
        "found": True,
        "cve_dir": cve_rel,
        "url_count": len(urls),
        "urls": urls[:50],
        "poc_count": len(pocs),
        "pocs": pocs[:50],
        "truncated": len(urls) > 50 or len(pocs) > 50,
    }


def _find_clone(root: Path, cve_dir: Path, repo: str | None) -> Path | None:
    clones = _local_clones(cve_dir, root)
    if not clones:
        return None
    if repo:
        repo_l = repo.strip().rstrip("/")
        name = repo_l.split("/")[-1]
        for c in clones:
            if c["repo"] == name or c["repo"] == repo_l:
                return (root / c["path"]).resolve()
            if c.get("url") and repo_l in c["url"]:
                return (root / c["path"]).resolve()
        return None
    return (root / clones[0]["path"]).resolve()


def get_poc_context(
    root: Path,
    cve_id: str,
    repo: str | None = None,
    max_bytes: int = 80_000,
) -> dict[str, Any]:
    cve = normalize_cve_id(cve_id)
    cve_dir = cve_year_dir(root, cve)
    if not cve_dir.is_dir():
        return {
            "caution": MALWARE_CAUTION,
            "cve_id": cve,
            "error": f"No local collection for {cve}",
        }

    clone_path = _find_clone(root, cve_dir, repo)
    if clone_path is None:
        return {
            "caution": MALWARE_CAUTION,
            "cve_id": cve,
            "error": "No local clone found"
            + (f" matching repo={repo!r}" if repo else ""),
            "hint": "Run stockpiler.sh update or check list_pocs()",
        }

    files = [p for p in _iter_repo_files(clone_path, max_depth=4) if p.is_file()]
    ranked = sorted(files, key=lambda p: _score_entry(p, clone_path), reverse=True)

    included: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    budget = max(1024, max_bytes)
    used = 0

    for path in ranked:
        rel = path.relative_to(clone_path).as_posix()
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": rel, "reason": str(exc)})
            continue

        if _is_probably_binary(path):
            skipped.append({"path": rel, "reason": "binary or non-text", "bytes": size})
            continue

        remaining = budget - used
        if remaining <= 0:
            skipped.append({"path": rel, "reason": "budget exhausted", "bytes": size})
            continue

        take = min(size, remaining)
        try:
            text, truncated = _read_text_capped(path, take)
        except OSError as exc:
            skipped.append({"path": rel, "reason": str(exc)})
            continue

        included.append(
            {
                "path": rel,
                "bytes_read": len(text.encode("utf-8", errors="replace")),
                "truncated": truncated or size > take,
                "content": text,
            }
        )
        used += included[-1]["bytes_read"]

    try:
        repo_rel = str(clone_path.resolve().relative_to(root.resolve()))
    except ValueError:
        repo_rel = str(clone_path)

    return {
        "caution": MALWARE_CAUTION,
        "cve_id": cve,
        "repo_path": repo_rel,
        "repo": clone_path.name,
        "max_bytes": budget,
        "bytes_used": used,
        "included": included,
        "skipped": skipped[:100],
        "skipped_total": len(skipped),
    }


def read_poc_file(
    root: Path,
    cve_id: str,
    repo: str,
    path: str,
    max_bytes: int = 100_000,
) -> dict[str, Any]:
    cve = normalize_cve_id(cve_id)
    cve_dir = cve_year_dir(root, cve)
    if not cve_dir.is_dir():
        return {"caution": MALWARE_CAUTION, "error": f"No local collection for {cve}"}

    clone_path = _find_clone(root, cve_dir, repo)
    if clone_path is None:
        return {"caution": MALWARE_CAUTION, "error": f"Repo not found: {repo}"}

    rel = path.lstrip("/").replace("\\", "/")
    if ".." in Path(rel).parts:
        raise PermissionError("Path escapes repo root")
    target = safe_join(clone_path, *Path(rel).parts)
    if not target.is_file():
        return {
            "caution": MALWARE_CAUTION,
            "error": f"File not found: {rel}",
            "repo": clone_path.name,
        }

    if _is_probably_binary(target):
        return {
            "caution": MALWARE_CAUTION,
            "path": rel,
            "error": "Refusing to read binary/non-text file",
            "bytes": target.stat().st_size,
        }

    text, truncated = _read_text_capped(target, max(1024, max_bytes))
    return {
        "caution": MALWARE_CAUTION,
        "cve_id": cve,
        "repo": clone_path.name,
        "path": rel,
        "truncated": truncated,
        "bytes_read": len(text.encode("utf-8", errors="replace")),
        "content": text,
    }
