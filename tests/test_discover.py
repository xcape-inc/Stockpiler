import subprocess
import tempfile
import unittest
from pathlib import Path

from stockpiler.discover import candidates


class DiscoveryTests(unittest.TestCase):
    def test_reads_cve_and_git_provenance_from_local_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "CVE-2026" / "CVE-2026-1001" / "1" / "fixture"
            repository.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.name", "Test"], check=True)
            (repository / "poc.py").write_text("pass\n")
            subprocess.run(["git", "-C", str(repository), "add", "poc.py"], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/xcape-inc/fixture.git"],
                check=True,
            )
            result = candidates(Path(temporary))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].vulnerability_ids, ("CVE-2026-1001",))
        self.assertEqual(result[0].source_url, "https://github.com/xcape-inc/fixture")


if __name__ == "__main__":
    unittest.main()
