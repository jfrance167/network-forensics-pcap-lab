import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES_PATTERN = re.compile(r"uses:\s*[^@\s]+@([^\s#]+)")
FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class RepositoryPolicyTests(unittest.TestCase):
    def workflow_text(self) -> str:
        return "\n".join(path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml")))

    def test_actions_are_pinned(self) -> None:
        references = USES_PATTERN.findall(self.workflow_text())
        self.assertGreater(len(references), 0)
        self.assertTrue(all(FULL_SHA_PATTERN.fullmatch(reference) for reference in references))

    def test_checkout_does_not_persist_credentials(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            if "actions/checkout" in text:
                self.assertIn("persist-credentials: false", text)

    def test_security_workflows_support_manual_dispatch(self) -> None:
        for name in ("bandit.yml", "codeql.yml"):
            self.assertIn("workflow_dispatch:", (WORKFLOWS / name).read_text(encoding="utf-8"))

    def test_codeql_runs_weekly(self) -> None:
        self.assertIn("schedule:", (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8"))

    def test_workflows_use_minimum_permissions(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            self.assertIn("permissions:\n  contents: read", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
