"""Audit engine for secscan."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime

from secfesc.shared import log_debug, log_info
from secfesc.shared.colors import BOLD, GREEN, RED, RESET, YELLOW

# Map a finding severity to (colour, glyph, summary-bucket).
_SEVERITY_STYLE = {
    "high": (RED, "✖", "errors"),
    "error": (RED, "✖", "errors"),
    "medium": (YELLOW, "⚠", "warnings"),
    "warning": (YELLOW, "⚠", "warnings"),
    "low": (YELLOW, "•", "notes"),
    "note": (YELLOW, "•", "notes"),
    "info": (GREEN, "ℹ", "notes"),
}


@dataclass
class AuditCategory:
    name: str
    description: str
    checks: list = field(default_factory=list)


@dataclass
class AuditFinding:
    category: str
    check_id: str
    title: str
    severity: str
    status: str
    description: str
    solution: str
    affected: str = ""

    @staticmethod
    def found(
        category: str,
        check_id: str,
        title: str,
        severity: str,
        description: str,
        solution: str,
        affected: str = "",
    ) -> "AuditFinding":
        """Convenience constructor for a 'found' finding (the common case)."""
        return AuditFinding(
            category=category,
            check_id=check_id,
            title=title,
            severity=severity,
            status="found",
            description=description,
            solution=solution,
            affected=affected,
        )


@dataclass
class AuditReport:
    hostname: str
    start_time: datetime
    end_time: datetime | None = None
    is_root: bool = False
    categories: list[AuditCategory] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float | None:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class AuditEngine:
    def __init__(self, verbose: bool = False, log_level: str = "INFO"):
        self.verbose = verbose
        self.log_level = log_level
        self.report = AuditReport(
            hostname=self._get_hostname(),
            start_time=datetime.now(),
            is_root=os.geteuid() == 0,
        )

    def _get_hostname(self) -> str:
        try:
            return os.uname().nodename
        except Exception:
            return "unknown"

    def run_category(self, category: str) -> list[AuditFinding]:
        """Run every registered check for *category* and return its findings."""
        from secfesc.secscan.core import registry

        log_info(f"Running category: {category}")
        return registry.run_category(category)

    def run_categories(self, categories: list[str]) -> AuditReport:
        """Run *categories* that have registered checks, honouring root needs."""
        from secfesc.secscan.core import registry

        ran: list[AuditCategory] = []
        for category in categories:
            if not registry.has_checks(category):
                log_debug(f"Skipping {category} - no checks implemented yet")
                continue
            if not self.report.is_root and self._requires_root(category):
                log_debug(f"Skipping {category} - requires root")
                self.report.warnings.append(f"Skipped '{category}' (run as root to include it)")
                continue
            findings = self.run_category(category)
            ran.append(
                AuditCategory(name=category, description=f"Category: {category}", checks=findings)
            )
            self.report.findings.extend(findings)

        self.report.categories = ran
        self.report.end_time = datetime.now()
        return self.report

    def run_full_audit(self) -> AuditReport:
        log_info("Starting full security audit")
        from secfesc.secscan.core import registry

        return self.run_categories(registry.registered_categories())

    def run_quick_audit(self) -> AuditReport:
        log_info("Starting quick security audit (no root required)")
        quick_categories = [
            "boot",
            "kernel",
            "network",
            "ports",
            "services",
            "logging",
            "ssh",
            "users",
            "groups",
            "authentication",
            "firewall",
            "cron",
            "permissions",
        ]
        return self.run_categories(quick_categories)

    def _requires_root(self, category: str) -> bool:
        # Categories that genuinely cannot run without root (e.g. reading file
        # contents). The boot/kernel/services/logging checks read only
        # world-readable sources (/proc/sys, systemctl queries), so they run as
        # a normal user and are deliberately not listed here.
        root_categories = [
            "files",
            "attributes",
        ]
        return category in root_categories

    @staticmethod
    def _severity_counts(report: AuditReport) -> dict[str, int]:
        counts = {"errors": 0, "warnings": 0, "notes": 0}
        for f in report.findings:
            _, _, bucket = _SEVERITY_STYLE.get(f.severity, (YELLOW, "•", "notes"))
            counts[bucket] += 1
        return counts

    def print_findings(self, report: AuditReport) -> None:
        """Print every finding, grouped by category, with colour and solution."""
        if not report.findings:
            print(f"\n  {GREEN}No findings — nothing flagged in the audited categories.{RESET}")
            return

        by_category: dict[str, list[AuditFinding]] = {}
        for f in report.findings:
            by_category.setdefault(f.category, []).append(f)

        for category in sorted(by_category):
            print(f"\n  {BOLD}{category.upper()}{RESET}")
            print("  " + "─" * 58)
            for f in by_category[category]:
                color, glyph, _ = _SEVERITY_STYLE.get(f.severity, (YELLOW, "•", "notes"))
                print(f"  {color}{glyph} [{f.check_id}] {f.title}{RESET}")
                print(f"      {f.description}")
                if f.affected:
                    print(f"      Affected: {f.affected}")
                if f.solution:
                    print(f"      → {f.solution}")

    def print_summary(self, report: AuditReport) -> None:
        self.print_findings(report)

        counts = self._severity_counts(report)
        print("\n" + "=" * 60)
        print("  SECSCAN AUDIT SUMMARY")
        print("=" * 60)
        print(f"  Host:         {report.hostname}")
        print(f"  Root access:  {'Yes' if report.is_root else 'No'}")
        print(
            f"  Duration:     {report.duration:.2f}s"
            if report.duration is not None
            else "  Duration:     running..."
        )
        print(f"  Categories:   {len(report.categories)}")
        print(
            f"  Findings:     {len(report.findings)}  "
            f"({RED}{counts['errors']} errors{RESET}, "
            f"{YELLOW}{counts['warnings']} warnings{RESET}, "
            f"{counts['notes']} notes)"
        )
        print("=" * 60)

        for warning in report.warnings:
            print(f"  {YELLOW}!{RESET} {warning}")

        if not report.is_root:
            print("\n  Note: Run with sudo for complete audit")
            print("        sudo secscan --full")
            print()
