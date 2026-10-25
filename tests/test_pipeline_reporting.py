"""End-to-end: synthetic $MFT folder -> pipeline -> reports -> reopen the saved case."""
import csv
import io
import json
from datetime import datetime, timezone

import pytest

from afd.core.case import Case
from afd.core.finding import Confidence
from afd.pipeline import AnalysisOptions, list_cases, load_case, run_analysis
from afd.reporting import build_context, findings_to_csv, render_html, write_reports
from afd.reporting.context import CONCLUSION_PLACEHOLDER

from tests.mft_builder import ft, when, write_mft

OLD = datetime(2019, 3, 4, 10, 0, 0, tzinfo=timezone.utc)
ROOT, WINDOWS, TEMP, DOCS = 5, 40, 41, 42


def _dir(entry, name, parent=ROOT):
    t = ft(when(), 1234567)
    return dict(entry=entry, name=name, parent=parent, is_dir=True, si=(t, t, t, t), fn=(t, t, t, t))


def _tampered_entries():
    t = ft(when(hours=1), 7654321)
    arrive = ft(when(hours=2), 3141592)
    old = ft(OLD)
    wiped = ft(when(hours=2, minutes=5), 1111111)
    return [
        _dir(WINDOWS, "Windows"), _dir(TEMP, "Temp", WINDOWS), _dir(DOCS, "Docs"),
        # timestomped: $SI set to 2019 whole seconds, edited after it arrived
        dict(entry=50, name="evil.exe", parent=TEMP, si=(old, old, ft(when(hours=2, minutes=3), 5550001), old),
             fn=(arrive, arrive, arrive, arrive)),
        # SDelete-style renamed deleted entry
        dict(entry=51, name="ZZZZZZZZ.ZZZ", parent=DOCS, in_use=False, si=(wiped,) * 4, fn=(wiped,) * 4, data=b""),
        # executable hidden in an Alternate Data Stream
        dict(entry=52, name="notes.txt", parent=DOCS, si=(t,) * 4, fn=(t,) * 4, data=b"plain text",
             ads=[("payload.exe", b"MZ" + b"\x90" * 200)]),
        # the wiping tool binary itself
        dict(entry=53, name="sdelete64.exe", parent=DOCS, si=(arrive,) * 4, fn=(arrive,) * 4, data=b"MZ\x90\x00"),
        # an ordinary file
        dict(entry=54, name="report.docx", parent=DOCS, si=(t,) * 4, fn=(t,) * 4, data=b"PK\x03\x04docx"),
    ]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AFD_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("AFD_EVIDENCE_DIR", str(tmp_path / "evidence"))
    art = tmp_path / "evidence" / "artifacts"
    art.mkdir(parents=True)
    write_mft(art / "$MFT", _tampered_entries())
    return art


def test_pipeline_runs_and_saves_case(env):
    case = Case("e2e", examiner="tester")
    steps = []
    result = run_analysis(env, case, AnalysisOptions(), progress=lambda m, f: steps.append(f))

    assert steps[-1] == 1.0
    modules = {m["key"]: m["status"] for m in result.modules}
    assert modules["timestomp"] == "ran" and modules["freespace"] == "skipped"
    assert modules["log_wiping"] == "skipped"            # no .evtx supplied

    found = {f.module for f in result.findings}
    assert {"timestomp", "file_wiping", "hidden_files", "tool_traces"} <= found
    ids = [f.id for f in result.findings]
    assert len(ids) == len(set(ids))                       # ids are unique
    assert {e.finding_id for e in result.timeline.entries} <= set(ids)   # timeline uses the final ids

    for name in ("findings.json", "timeline.json", "case_summary.json"):
        assert (case.dir / name).exists()
    actions = [e["action"] for e in case.read_log()]
    assert actions[0] == "analysis_started" and actions[-1] == "analysis_finished"
    assert any(e["action"] == "evidence_hashed" and e["path"].endswith("$MFT") for e in case.read_log())


def test_reopened_case_matches(env):
    result = run_analysis(env, Case("e2e2", examiner="tester"))
    assert "e2e2" in list_cases()
    again = load_case("e2e2")
    assert [f.to_dict() for f in again.findings] == [f.to_dict() for f in result.findings]
    assert again.evidence and again.evidence[0]["sha256"] == result.evidence[0]["sha256"]
    assert again.modules == result.modules


def test_reports_written_and_logged(env):
    case = Case("e2e3", examiner="tester")
    result = run_analysis(env, case)
    out = write_reports(result, case, Confidence.LOW, "My own conclusion.", case.verify_evidence())

    html = out["html"].read_text(encoding="utf-8")
    assert "My own conclusion." in html and CONCLUSION_PLACEHOLDER not in html
    assert result.evidence[0]["sha256"] in html
    assert "SHA-256 matches" in html
    assert out["pdf"].read_bytes()[:5] == b"%PDF-"
    rows = list(csv.DictReader(io.StringIO(out["csv"].read_text(encoding="utf-8"))))
    assert len(rows) == len(result.findings)
    assert json.loads(out["json"].read_text(encoding="utf-8"))["findings"]
    logged = [e for e in case.read_log() if e["action"] == "report_written"]
    assert {e["kind"] for e in logged} == {"html", "pdf", "csv", "json"}
    assert all(len(e["sha256"]) == 64 for e in logged)


def test_report_without_conclusion_shows_placeholder_and_filters(env):
    case = Case("e2e4", examiner="tester")
    result = run_analysis(env, case)
    ctx = build_context(result, case, Confidence.HIGH)
    assert ctx["conclusion_missing"] and ctx["conclusion"] == CONCLUSION_PLACEHOLDER
    assert all(f["confidence"] == "HIGH" for f in ctx["findings"])
    assert ctx["omitted"] == sum(f.confidence < Confidence.HIGH for f in result.findings)
    assert CONCLUSION_PLACEHOLDER in render_html(ctx)


def test_html_escapes_file_names(env):
    case = Case("e2e5", examiner="<script>x</script>")
    result = run_analysis(env, case)
    html = render_html(build_context(result, case))
    assert "<script>x</script>" not in html


def test_csv_flattens_lists():
    from afd.core.finding import Finding
    f = Finding(module="timestomp", technique="T", mitre="T1070.006", title="t", confidence=Confidence.LOW,
                score=1, subject="s", artifact="a", reasons=["r1", "r2"], evidence={"k": [1, 2]}, id="TS-0001")
    row = next(csv.DictReader(io.StringIO(findings_to_csv([f]))))
    assert row["reasons"] == "r1 | r2" and json.loads(row["evidence"]) == {"k": [1, 2]}
