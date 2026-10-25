"""Report generator (HTML and PDF) and CSV/JSON export."""
from __future__ import annotations

from pathlib import Path

from afd.core.case import Case, hash_file
from afd.core.finding import Confidence
from afd.reporting.context import build_context
from afd.reporting.export import findings_to_csv, result_to_json
from afd.reporting.html_report import render_html
from afd.reporting.pdf_report import render_pdf


def write_reports(
    result,
    case: Case,
    min_confidence: Confidence = Confidence.MEDIUM,
    examiner_conclusion: str = "",
    verification: list[dict] | None = None,
) -> dict[str, Path]:
    """Write report.html, report.pdf, findings.csv and analysis.json to the case folder,
    hash each output and log it in the custody log. Returns {kind: path}."""
    ctx = build_context(result, case, min_confidence, examiner_conclusion, verification)
    out = {
        "html": case.dir / "report.html",
        "pdf": case.dir / "report.pdf",
        "csv": case.dir / "findings.csv",
        "json": case.dir / "analysis.json",
    }
    out["html"].write_text(render_html(ctx), encoding="utf-8")
    render_pdf(ctx, out["pdf"])
    out["csv"].write_text(findings_to_csv(result.findings), encoding="utf-8", newline="")
    out["json"].write_text(result_to_json(result), encoding="utf-8")
    for kind, path in out.items():
        case.log("report_written", kind=kind, file=str(path), min_confidence=min_confidence.name,
                 **hash_file(path))
    return out


__all__ = ["build_context", "render_html", "render_pdf", "findings_to_csv", "result_to_json", "write_reports"]
