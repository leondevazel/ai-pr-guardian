import json
import re
from pathlib import Path

from guardian.models import Finding
from guardian.orchestrator import decide, decide_on_all, review_pr

SAMPLE_DIFF = (Path(__file__).parent / "fixtures" / "sample.diff").read_text()
REPO = str(Path(__file__).parent / "fixtures" / "fakerepo")


def finding(severity="block", confidence=0.9, agent="security", line=12, category="sql-injection"):
    return Finding(
        agent=agent,
        file="app/db.py",
        line=line,
        severity=severity,
        category=category,
        claim="claim",
        evidence="evidence",
        confidence=confidence,
    )


# --- decide(): the threshold rule from agent.md §4, deterministic and LLM-free ---
#
# Only the security agent can block. On the benchmark it filed 6 findings, all 6 real
# vulnerabilities, 0 false positives — while architecture and business_logic together produced
# every one of the 13 false positives (RESULTS.md). Their findings still ship, as advisory.


def test_block_finding_at_threshold_blocks():
    assert decide([finding(severity="block", confidence=0.7)]) == "block"


def test_block_finding_below_threshold_does_not_block():
    assert decide([finding(severity="block", confidence=0.69)]) == "approve"


def test_architecture_finding_never_blocks_however_confident():
    assert decide([finding(agent="architecture", severity="block", confidence=0.99)]) == "approve"


def test_business_logic_finding_never_blocks():
    assert decide([finding(agent="business_logic", severity="warn", confidence=0.95)]) == "approve"


def test_security_finding_still_blocks_alongside_advisory_ones():
    findings = [
        finding(agent="architecture", severity="block", confidence=0.99),
        finding(agent="security", severity="block", confidence=0.8),
    ]
    assert decide(findings) == "block"


def test_decide_on_all_keeps_the_unfiltered_view_for_the_benchmark():
    assert decide_on_all([finding(agent="architecture", severity="block", confidence=0.9)]) == "block"


def test_block_finding_below_threshold_still_requests_changes_if_warn_qualifies():
    findings = [finding(severity="block", confidence=0.69), finding(severity="warn", confidence=0.6)]
    assert decide(findings) == "request_changes"


def test_warn_finding_at_threshold_requests_changes():
    assert decide([finding(severity="warn", confidence=0.5)]) == "request_changes"


def test_nits_alone_are_approved():
    assert decide([finding(severity="nit", confidence=1.0)]) == "approve"


def test_no_findings_is_approve():
    assert decide([]) == "approve"


# --- review_pr(): the 3-round pipeline ---


class ScriptedClient:
    """Keys responses off the agent name and round marker in the system prompt, because
    round 1 runs agents in parallel and call order is not deterministic."""

    def __init__(self, round1: dict, round2: dict | None = None, chief: str = ""):
        self.round1 = round1
        self.round2 = round2 or {}
        self.chief = chief
        self.calls: list[dict] = []

    def complete(self, system: str, user: str, model: str) -> str:
        self.calls.append({"system": system, "user": user, "model": model})
        agent = re.search(r"You are the (\w+) reviewer", system).group(1)
        if agent == "chief":
            return self.chief
        if "REBUTTAL" in system:
            return self.round2.get(agent, "[]")
        return self.round1.get(agent, "[]")


def findings_json(*items):
    return json.dumps(
        [
            {
                "file": "app/db.py",
                "line": item.get("line", 12),
                "severity": item.get("severity", "block"),
                "category": item.get("category", "sql-injection"),
                "claim": item.get("claim", "SQL injection via f-string"),
                "evidence": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "confidence": item.get("confidence", 0.9),
            }
            for item in items
        ]
    )


CHIEF_KEEPS_ALL = json.dumps({"kept": [0], "rationale": "Confirmed SQL injection on line 12."})


def test_end_to_end_produces_verdict_with_kept_findings():
    client = ScriptedClient(
        round1={"security": findings_json({})},
        chief=CHIEF_KEEPS_ALL,
    )
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert verdict.decision == "block"
    assert len(verdict.findings) == 1
    assert "line 12" in verdict.rationale


def test_findings_without_a_line_never_reach_the_chief():
    bad = json.dumps([{"file": "app/db.py", "severity": "block", "claim": "vague", "confidence": 1.0}])
    client = ScriptedClient(round1={"security": bad}, chief=json.dumps({"kept": [], "rationale": "Nothing concrete."}))
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert verdict.decision == "approve"
    assert verdict.findings == []


def test_rebuttal_round_shows_agents_their_peers_findings():
    client = ScriptedClient(
        round1={
            "security": findings_json({}),
            "architecture": findings_json({"severity": "warn", "category": "layering"}),
        },
        chief=CHIEF_KEEPS_ALL,
    )
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    rebuttal_prompts = [c["user"] for c in client.calls if "REBUTTAL" in c["system"]]
    assert rebuttal_prompts, "expected a rebuttal round"
    assert any("layering" in p for p in rebuttal_prompts)


def test_rebuttal_can_lower_confidence_below_block_threshold():
    client = ScriptedClient(
        round1={"security": findings_json({})},
        round2={"security": json.dumps([{"index": 0, "confidence": 0.2, "rebuttal": "Input is an int."}])},
        chief=CHIEF_KEEPS_ALL,
    )
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert verdict.decision == "approve"
    assert verdict.findings[0].confidence == 0.2


def test_agents_with_no_findings_skip_the_rebuttal_call():
    client = ScriptedClient(round1={}, chief=json.dumps({"kept": [], "rationale": "Clean."}))
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert not [c for c in client.calls if "REBUTTAL" in c["system"]]


def test_chief_cannot_invent_findings_it_only_selects_indices():
    client = ScriptedClient(
        round1={"security": findings_json({})},
        chief=json.dumps({"kept": [0, 99], "rationale": "Kept the real one."}),
    )
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert len(verdict.findings) == 1


def test_advisory_findings_are_returned_separately_from_blocking_ones():
    client = ScriptedClient(
        round1={"architecture": findings_json({"severity": "block", "category": "layering"})},
        chief=CHIEF_KEEPS_ALL,
    )
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert verdict.decision == "approve"
    assert verdict.findings == []
    assert [f.category for f in verdict.advisory] == ["layering"]


def test_security_findings_stay_in_the_blocking_list():
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    verdict = review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])

    assert verdict.decision == "block"
    assert [f.agent for f in verdict.findings] == ["security"]
    assert verdict.advisory == []


# --- progress events: the website streams the debate as it happens ---


def test_emits_each_agents_first_round_findings():
    events = []
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [], on_event=events.append)

    round1 = [e for e in events if e["type"] == "findings" and e["round"] == 1]
    assert sorted(e["agent"] for e in round1) == ["architecture", "business_logic", "security"]
    security = next(e for e in round1 if e["agent"] == "security")
    assert security["findings"][0]["category"] == "sql-injection"


def test_stages_are_announced_in_order():
    events = []
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [], on_event=events.append)

    stages = [e["stage"] for e in events if e["type"] == "stage"]
    assert stages == ["round1", "rebuttal", "chief"]


def test_no_callback_means_no_change_in_behaviour():
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    assert review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: []).decision == "block"


# --- output language: Korean readers get Korean prose, code stays as written ---


def test_korean_review_asks_every_writer_for_korean_prose():
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [], language="ko")

    writers = [c for c in client.calls if "REBUTTAL" not in c["system"]]
    assert writers and all("Korean" in c["system"] for c in writers)


def test_english_prompts_are_unchanged_from_the_benchmarked_ones():
    client = ScriptedClient(round1={"security": findings_json({})}, chief=CHIEF_KEEPS_ALL)
    review_pr(REPO, SAMPLE_DIFF, client, run_semgrep=lambda *_: [])
    assert not any("Korean" in c["system"] for c in client.calls)
