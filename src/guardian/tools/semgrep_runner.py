import json
import subprocess

from guardian.models import ToolFinding

# Free rulesets. security-audit alone misses common data-flow bugs (see agent.md §7),
# so p/python is layered on for broader lint-level coverage.
RULESETS = ["p/security-audit", "p/python"]

SEVERITY_MAP = {"ERROR": "block", "WARNING": "warn", "INFO": "nit"}


def parse_semgrep_json(raw: dict) -> list[ToolFinding]:
    return [
        ToolFinding(
            file=result["path"].replace("\\", "/"),
            line=result["start"]["line"],
            rule_id=result["check_id"],
            message=result["extra"]["message"].strip(),
            severity=SEVERITY_MAP.get(result["extra"]["severity"], "nit"),
        )
        for result in raw.get("results", [])
    ]


def run_semgrep(repo_path: str, changed_files: list[str], timeout: int = 300) -> list[ToolFinding]:
    if not changed_files:
        return []

    config_args = [arg for ruleset in RULESETS for arg in ("--config", ruleset)]
    proc = subprocess.run(
        ["semgrep", *config_args, "--json", "--quiet", *changed_files],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if not proc.stdout.strip():
        return []
    return parse_semgrep_json(json.loads(proc.stdout))
