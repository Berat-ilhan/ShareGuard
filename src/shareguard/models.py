from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


REPORT_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), "GITHUB_TOKEN"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"), "GITHUB_TOKEN"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS_ACCESS_KEY"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "JWT",
    ),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GITLAB_TOKEN"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "SLACK_TOKEN"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "GOOGLE_API_KEY"),
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "SERVICE_KEY"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "NPM_TOKEN"),
)
REPORT_ASSIGNED_SECRET_RE = re.compile(
    r"(?ix)(?P<prefix>"
    r"(?<![A-Za-z0-9])(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    r"(?:api[_-]?key|client[_-]?secret|secret(?:[_-]?key)?|"
    r"auth[_-]?token|access[_-]?token|token|password|passwd|pwd)"
    r"(?:[_-][A-Za-z][A-Za-z0-9]*)*(?![A-Za-z0-9_])"
    r"\s*(?::(?!:)|=(?!=))\s*[\"']?"
    r")(?P<value>[A-Za-z0-9_./+~=:@%-]{12,})"
)


def sanitize_report_text(value: str) -> str:
    """Make untrusted filesystem/report text UTF-8 safe and redact token shapes.

    Filesystem names may contain surrogateescape code points on POSIX. Rendering
    them as a literal ``\\udcXX`` sequence preserves a useful clue without making
    UTF-8 report writes fail. Normal Unicode, including Turkish text, is kept.
    """

    safe = value.encode("utf-8", errors="backslashreplace").decode("utf-8")
    for pattern, label in REPORT_SECRET_PATTERNS:
        safe = pattern.sub(f"[REDACTED:{label}]", safe)
    safe = REPORT_ASSIGNED_SECRET_RE.sub(
        lambda match: f"{match.group('prefix')}[REDACTED:SECRET]",
        safe,
    )
    return safe


def sanitize_report_data(value: Any) -> Any:
    """Recursively sanitize every textual value crossing the report boundary."""

    if isinstance(value, str):
        return sanitize_report_text(value)
    if isinstance(value, Path):
        return sanitize_report_text(str(value))
    if isinstance(value, dict):
        return {
            sanitize_report_text(str(key)): sanitize_report_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_report_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_report_data(item) for item in value)
    return value


def redact_report_evidence(
    value: Any,
    replacements: Iterable[tuple[str, str]],
) -> Any:
    """Replace process-local evidence anywhere inside report-bound data.

    Keeping ``local_evidence`` out of the serialized finding is necessary but
    not sufficient: the same value could also occur in a file name, an error,
    or an excluded path. Exact-value replacement closes that second route.
    """

    ordered = tuple(
        sorted(
            ((raw, masked) for raw, masked in replacements if raw),
            key=lambda item: len(item[0]),
            reverse=True,
        )
    )
    if isinstance(value, str):
        safe = value
        for raw, masked in ordered:
            safe = safe.replace(raw, masked)
        return safe
    if isinstance(value, Path):
        return redact_report_evidence(str(value), ordered)
    if isinstance(value, dict):
        return {
            redact_report_evidence(str(key), ordered): redact_report_evidence(item, ordered)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_report_evidence(item, ordered) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_report_evidence(item, ordered) for item in value)
    return value


class Severity(str, Enum):
    BLOCKER = "blocker"
    REVIEW = "review"
    INFO = "info"


class RecommendedAction(str, Enum):
    EXCLUDE = "exclude"
    REVIEW = "review"
    KEEP = "keep"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: Severity
    category: str
    relative_path: str
    title: str
    explanation: str
    detector: str
    recommended_action: RecommendedAction = RecommendedAction.REVIEW
    line_number: int | None = None
    masked_evidence: str | None = None
    # Full evidence is intentionally process-local. It is available to the
    # desktop UI for an on-device review, but must never cross the shareable
    # report boundary in ``to_dict``.
    local_evidence: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        # Keep this as an explicit export allow-list. ``asdict(self)`` would
        # silently start exporting any future process-local field.
        data = {
            "finding_id": self.finding_id,
            "severity": self.severity.value,
            "category": self.category,
            "relative_path": self.relative_path,
            "title": self.title,
            "explanation": self.explanation,
            "detector": self.detector,
            "recommended_action": self.recommended_action.value,
            "line_number": self.line_number,
            "masked_evidence": self.masked_evidence,
        }
        replacement = (
            [(self.local_evidence, self.masked_evidence or "[REDACTED:LOCAL_EVIDENCE]")]
            if self.local_evidence
            else []
        )
        sanitized = sanitize_report_data(redact_report_evidence(data, replacement))
        assert isinstance(sanitized, dict)
        return sanitized


def report_evidence_redactions(
    findings: Iterable[Finding],
) -> tuple[tuple[str, str], ...]:
    """Return deterministic exact-value replacements for a report boundary."""

    replacements: dict[str, str] = {}
    for finding in findings:
        if finding.local_evidence:
            replacements.setdefault(
                finding.local_evidence,
                finding.masked_evidence or "[REDACTED:LOCAL_EVIDENCE]",
            )
    return tuple(sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True))


@dataclass
class ScanStats:
    files_seen: int = 0
    directories_seen: int = 0
    bytes_seen: int = 0
    skipped_items: int = 0
    errors: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = ""

    @property
    def blockers(self) -> list[Finding]:
        return [item for item in self.findings if item.severity is Severity.BLOCKER]

    @property
    def reviews(self) -> list[Finding]:
        return [item for item in self.findings if item.severity is Severity.REVIEW]

    @property
    def infos(self) -> list[Finding]:
        return [item for item in self.findings if item.severity is Severity.INFO]

    @property
    def verdict(self) -> str:
        if self.blockers:
            return "BLOCKED"
        if self.reviews or self.errors:
            return "REVIEW"
        return "READY"

    def sorted_findings(self) -> list[Finding]:
        order = {Severity.BLOCKER: 0, Severity.REVIEW: 1, Severity.INFO: 2}
        return sorted(
            self.findings,
            key=lambda item: (order[item.severity], item.relative_path, item.finding_id),
        )

    def to_dict(self) -> dict[str, Any]:
        data = {
            # Reports are intended to be shareable. Do not leak the local user's
            # absolute home path into JSON output.
            "root_name": self.root.name,
            "scanned_at": self.scanned_at,
            "verdict": self.verdict,
            "summary": {
                "blockers": len(self.blockers),
                "review": len(self.reviews),
                "info": len(self.infos),
            },
            "stats": self.stats.to_dict(),
            "errors": list(self.errors),
            "findings": [item.to_dict() for item in self.sorted_findings()],
        }
        sanitized = sanitize_report_data(
            redact_report_evidence(data, report_evidence_redactions(self.findings))
        )
        assert isinstance(sanitized, dict)
        return sanitized


@dataclass(frozen=True)
class PackagingResult:
    output_dir: Path
    clean_dir: Path
    zip_path: Path
    html_report: Path
    json_report: Path
    manifest_path: Path
    excluded_path: Path
    excluded: tuple[str, ...]
    clean_scan: ScanResult


def unique_paths(paths: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({Path(path).as_posix().strip("/") for path in paths if path}))
