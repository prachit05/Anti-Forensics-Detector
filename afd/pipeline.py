"""One analysis run: collect evidence, run the six detectors, correlate, build the timeline.

Both the command line (run_detectors.py) and the dashboard (app.py) call run_analysis(),
so they always produce the same findings for the same input.

Every run writes three files to the case folder, next to custody_log.jsonl:
  findings.json      every finding (all confidence levels)
  timeline.json      dated entries, episodes and undated findings
  case_summary.json  input, options, artifact counts and which modules ran or were skipped
load_case() reads them back so a finished case can be reopened without re-parsing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from afd.analysis import (
    Timeline,
    build_timeline,
    correlate_findings,
    detect_log_anomalies,
    detect_mft_anomalies,
)
from afd.core.case import Case
from afd.core.finding import Finding, assign_ids, sort_findings
from afd.detectors import file_wiping, freespace, hidden_files, log_wiping, timestomp, tool_traces
from afd.parsers import collector, evtx_parser, image_reader, mft_parser, prefetch_parser, registry_parser

TOOL_VERSION = "1.0"
MAIN_LOGS = ("security.evtx", "system.evtx", "application.evtx")

# (key, label shown on screen) in the order the modules run
MODULES = [
    ("timestomp", "1. Timestomping"),
    ("log_wiping", "2. Log wiping"),
    ("file_wiping", "3. File wiping / secure delete"),
    ("freespace", "4. Free-space wiping"),
    ("hidden_files", "5. Hidden / disguised files"),
    ("tool_traces", "6. Anti-forensic tool traces"),
    ("ml_anomaly", "Optional: ML (Isolation Forest)"),
]


@dataclass
class AnalysisOptions:
    all_logs: bool = False                 # parse every .evtx, not only Security/System/Application
    reference_time: datetime | None = None # acquisition time, for the "date in the future" check
    ml: bool = False                       # run the Isolation Forest module


@dataclass
class AnalysisResult:
    case_name: str
    case_dir: Path
    examiner: str
    source: str
    options: dict
    started_utc: str
    finished_utc: str = ""
    artifacts: dict = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)
    modules: list[dict] = field(default_factory=list)   # {key, label, status, findings, note}
    findings: list[Finding] = field(default_factory=list)
    timeline: Timeline = field(default_factory=Timeline)

    def summary_dict(self) -> dict:
        return {
            "tool_version": TOOL_VERSION,
            "case_name": self.case_name,
            "examiner": self.examiner,
            "source": self.source,
            "options": self.options,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
            "artifacts": self.artifacts,
            "modules": self.modules,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_analysis(
    source: Path,
    case: Case,
    opts: AnalysisOptions | None = None,
    progress: Callable[[str, float], None] | None = None,
) -> AnalysisResult:
    """Run the full pipeline on a disk image or a folder of exported artifacts.

    progress(message, fraction_done) is called before each step (for a progress bar).
    """
    opts = opts or AnalysisOptions()
    source = Path(source)
    say = progress or (lambda msg, frac: None)
    result = AnalysisResult(
        case_name=case.name, case_dir=case.dir, examiner=case.examiner, source=str(source),
        options={"all_logs": opts.all_logs, "ml": opts.ml,
                 "reference_time": opts.reference_time.isoformat() if opts.reference_time else None},
        started_utc=_now(),
    )
    case.log("analysis_started", source=str(source), **result.options)

    def module(key: str, status: str, found: list[Finding] | None = None, note: str = ""):
        label = dict(MODULES)[key]
        result.modules.append({"key": key, "label": label, "status": status,
                               "findings": len(found or []), "note": note})
        if status == "ran":
            case.log("detector_run", detector=key, findings=len(found or []))
        else:
            case.log("detector_skipped", detector=key, reason=note)
        return found or []

    is_image = source.is_file() and source.suffix.lower() in collector.IMAGE_EXTENSIONS

    say("Collecting and hashing evidence", 0.02)
    arts = collector.collect(source, case)
    result.artifacts = arts.summary()
    result.evidence = list(case.evidence)

    findings: list[Finding] = []
    mft_df = None
    if arts.mft:
        say("Parsing $MFT", 0.10)
        mft_df = mft_parser.load_mft(arts.mft[0])
        case.log("mft_parsed", file=str(arts.mft[0]), entries=len(mft_df))

    no_mft = "no $MFT in the input"

    # 1. Timestomping
    say("Module 1/6: timestomping", 0.25)
    if mft_df is not None:
        findings += module("timestomp", "ran", timestomp.detect(mft_df, reference_time=opts.reference_time))
    else:
        module("timestomp", "skipped", note=no_mft)

    # 2. Log wiping
    say("Module 2/6: parsing event logs", 0.35)
    logs = []
    for path in arts.evtx:
        if not opts.all_logs and path.name.lower() not in MAIN_LOGS:
            continue
        df, info = evtx_parser.load_evtx(path)
        case.log("evtx_parsed", file=path.name, records=info["records"], parse_errors=info["parse_errors"])
        logs.append((df, info))
    if logs:
        note = ""
        if not any(info.get("file", "").lower() == "system.evtx" for _, info in logs):
            note = "System.evtx not supplied: restarts and clock changes cannot be ruled out for gaps"
        findings += module("log_wiping", "ran", log_wiping.detect(logs), note)
    else:
        module("log_wiping", "skipped", note="no Security/System/Application .evtx in the input")

    # 3. File wiping
    say("Module 3/6: file wiping", 0.50)
    if mft_df is not None:
        findings += module("file_wiping", "ran", file_wiping.detect(mft_df))
    else:
        module("file_wiping", "skipped", note=no_mft)

    # 4. Free-space wiping (needs the raw image: exported files carry no unallocated space)
    say("Module 4/6: free-space sampling", 0.60)
    if is_image:
        findings += module("freespace", "ran", freespace.detect_from_image(source))
    else:
        module("freespace", "skipped", note="input is an artifact folder; unallocated space needs a disk image")

    # 5. Hidden / disguised files
    say("Module 5/6: ADS and header mismatch", 0.70)
    if mft_df is not None:
        note = "no disk image: header check covers resident files only"
        if is_image:
            # big files keep their data outside the $MFT: read their first bytes from the image
            wanted = hidden_files.head_candidates(mft_df)
            heads = image_reader.read_file_heads(source, wanted)
            case.log("file_heads_read", candidates=len(wanted), read=len(heads))
            mft_df = hidden_files.with_heads(mft_df, heads)
            note = f"read headers of {len(heads):,} non-resident file(s) from the image"
        findings += module("hidden_files", "ran", hidden_files.detect(mft_df), note)
    else:
        module("hidden_files", "skipped", note=no_mft)

    # 6. Tool traces
    say("Module 6/6: prefetch, registry and MFT tool traces", 0.78)
    prefetch_df = None
    if arts.prefetch:
        prefetch_df, _errors = prefetch_parser.load_prefetch_dir(arts.prefetch[0].parent)
        case.log("prefetch_parsed", records=len(prefetch_df))
    reg_data = registry_parser.load_registry_artifacts(arts.registry) if arts.registry else None
    if prefetch_df is None and reg_data is None and mft_df is None:
        module("tool_traces", "skipped", note="no prefetch, registry hives or $MFT in the input")
    else:
        missing = [n for n, v in (("prefetch", prefetch_df), ("registry", reg_data), ("$MFT", mft_df)) if v is None]
        note = f"not supplied: {', '.join(missing)}" if missing else ""
        findings += module("tool_traces", "ran",
                           tool_traces.detect(prefetch_df=prefetch_df, registry_data=reg_data, mft=mft_df), note)

    # Optional ML
    if opts.ml:
        say("Optional: Isolation Forest", 0.85)
        ml = (detect_log_anomalies(logs) if logs else []) + \
             (detect_mft_anomalies(mft_df) if mft_df is not None else [])
        findings += module("ml_anomaly", "ran", ml)
    else:
        module("ml_anomaly", "skipped", note="not selected")

    # Correlation, campaign detection and timeline (Stage 5)
    say("Correlating findings and building the timeline", 0.92)
    updated, campaigns = correlate_findings(findings)
    findings = assign_ids(sort_findings(updated + campaigns))   # final ids before the timeline uses them
    result.findings = findings
    result.timeline = build_timeline(findings)
    result.finished_utc = _now()

    save_result(result, case)
    say("Done", 1.0)
    return result


def save_result(result: AnalysisResult, case: Case) -> None:
    """Write findings.json, timeline.json and case_summary.json and log each write."""
    outputs = {
        "findings.json": [f.to_dict() for f in result.findings],
        "timeline.json": result.timeline.to_dict(),
        "case_summary.json": result.summary_dict(),
    }
    for name, data in outputs.items():
        path = case.dir / name
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        case.log("output_written", file=str(path))
    case.log("analysis_finished", findings=len(result.findings), timeline_entries=len(result.timeline.entries))


def list_cases() -> list[str]:
    """Names of case folders that contain a finished analysis, newest first."""
    from afd.core.config import get_paths
    root = get_paths()["cases_dir"]
    done = [p for p in root.iterdir() if (p / "findings.json").exists()]
    return [p.name for p in sorted(done, key=lambda p: (p / "findings.json").stat().st_mtime, reverse=True)]


def load_case(name: str, examiner: str | None = None) -> AnalysisResult:
    """Reopen a finished case from its saved JSON files (no re-parsing of evidence)."""
    case = Case(name, examiner)
    summary_file = case.dir / "case_summary.json"
    summary = json.loads(summary_file.read_text(encoding="utf-8")) if summary_file.exists() else {}
    raw = json.loads((case.dir / "findings.json").read_text(encoding="utf-8"))
    findings = [Finding.from_dict(d) for d in raw]
    case.log("case_opened", findings=len(findings))
    return AnalysisResult(
        case_name=name, case_dir=case.dir,
        examiner=summary.get("examiner", case.examiner),
        source=summary.get("source", "(unknown: case saved before Stage 6)"),
        options=summary.get("options", {}),
        started_utc=summary.get("started_utc", ""), finished_utc=summary.get("finished_utc", ""),
        artifacts=summary.get("artifacts", {}),
        evidence=case.load_evidence_from_log(),
        modules=summary.get("modules", []),
        findings=findings,
        timeline=build_timeline(findings),
    )
