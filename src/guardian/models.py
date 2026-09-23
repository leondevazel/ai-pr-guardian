from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["block", "warn", "nit"]
Decision = Literal["approve", "request_changes", "block"]


@dataclass
class Hunk:
    start_line: int
    added_lines: list[tuple[int, str]]
    context: str
    removed_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class ChangedFile:
    path: str
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class PRContext:
    files: list[ChangedFile] = field(default_factory=list)


@dataclass
class ToolFinding:
    file: str
    line: int
    rule_id: str
    message: str
    severity: Severity


@dataclass
class Finding:
    agent: str
    file: str
    line: int
    severity: Severity
    category: str
    claim: str
    evidence: str
    confidence: float


@dataclass
class Verdict:
    decision: Decision
    findings: list[Finding]
    rationale: str
