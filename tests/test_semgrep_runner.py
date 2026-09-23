import json
from pathlib import Path

from guardian.tools.semgrep_runner import parse_semgrep_json

RAW = json.loads((Path(__file__).parent / "fixtures" / "semgrep_output.json").read_text())


def test_extracts_rule_id_file_and_line():
    findings = parse_semgrep_json(RAW)
    subprocess_finding = next(f for f in findings if "subprocess-shell-true" in f.rule_id)
    assert subprocess_finding.line == 5
    assert subprocess_finding.file.endswith("app/unsafe.py")


def test_maps_semgrep_severity_to_our_scale():
    findings = parse_semgrep_json(RAW)
    by_rule = {f.rule_id.split(".")[-1]: f.severity for f in findings}
    assert by_rule["subprocess-shell-true"] == "block"  # semgrep ERROR
    assert by_rule["eval-detected"] == "warn"  # semgrep WARNING


def test_normalizes_windows_paths_to_forward_slashes():
    findings = parse_semgrep_json(RAW)
    assert all("\\" not in f.file for f in findings)


def test_empty_results_yield_empty_list():
    assert parse_semgrep_json({"results": []}) == []


def test_missing_results_key_does_not_raise():
    assert parse_semgrep_json({}) == []
