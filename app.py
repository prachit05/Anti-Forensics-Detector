"""Streamlit dashboard for the Anti-Forensics Detector (Stage 6).

Run:  streamlit run app.py

Sidebar: start a new analysis (disk image or artifact folder) or reopen a saved case.
Tabs:
  Overview            counts per confidence level, which modules ran, episode summary
  Findings            filterable list; pick one to see its reasons, innocent explanations and raw evidence
  Timeline            chart and table of the cover-up sequence, grouped into episodes
  Evidence & custody  hashes, a re-verify button, and the full chain-of-custody log
  Report & export     examiner's conclusion box, HTML/PDF report, CSV/JSON downloads

All analysis is done by afd.pipeline (the same code as run_detectors.py); this file only displays it.
"""
from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from afd.analysis import build_timeline
from afd.core.case import Case
from afd.core.config import get_paths, onedrive_warnings
from afd.core.finding import Confidence
from afd.parsers.collector import IMAGE_EXTENSIONS
from afd.parsers.image_reader import media_hash
from afd.pipeline import AnalysisOptions, list_cases, load_case, run_analysis
from afd.reporting import findings_to_csv, result_to_json, write_reports

LEVEL_COLOURS = {"HIGH": "#b3261e", "MEDIUM": "#b26a00", "LOW": "#3a6ea5"}
LEVELS = ["HIGH", "MEDIUM", "LOW"]

st.set_page_config(page_title="Anti-Forensics Detector", page_icon="🔎", layout="wide")


# ----------------------------------------------------------------------------- helpers
def fmt_time(t) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t else ""


def findings_frame(findings) -> pd.DataFrame:
    return pd.DataFrame([{
        "ID": f.id, "Confidence": f.confidence.name, "Score": f.score, "Module": f.module,
        "Finding": f.title, "Time (UTC)": fmt_time(f.event_time), "Artifact": f.artifact,
    } for f in findings])


BADGE_COLOURS = {"HIGH": "red", "MEDIUM": "orange", "LOW": "blue"}


def badge(level: str) -> str:
    """Coloured confidence label in Streamlit markdown, e.g. :red[**HIGH**]."""
    return f":{BADGE_COLOURS[level]}[**{level}**]"


def set_result(result, case):
    st.session_state.result = result
    st.session_state.case = case
    st.session_state.verification = None
    st.session_state.reports = None
    st.session_state.media_hash = None


# ----------------------------------------------------------------------------- sidebar
paths = get_paths()
with st.sidebar:
    st.title("🔎 Anti-Forensics Detector")
    st.caption("Windows / NTFS. Findings mean *likely*, never proof.")
    examiner = st.text_input("Examiner", value=getpass.getuser())
    mode = st.radio("Input", ["New analysis", "Open saved case"], horizontal=True)

    if mode == "New analysis":
        source = st.text_input("Disk image (E01/dd/raw/fixed VHD) or artifact folder",
                               value=str(paths["evidence_dir"]))
        case_name = st.text_input("Case name", value=f"case_{datetime.now():%Y%m%d_%H%M%S}")
        with st.expander("Options"):
            use_ml = st.checkbox("Run ML anomaly detection (Isolation Forest)")
            all_logs = st.checkbox("Parse every .evtx (slower)")
            ref = st.text_input("Acquisition time (UTC, optional)", placeholder="2026-10-25T09:30:00Z",
                                help="Dates later than this are reported as impossible future dates.")
        if st.button("Run analysis", type="primary", use_container_width=True):
            src = Path(source.strip().strip('"'))
            reference = None
            try:
                if ref.strip():
                    reference = datetime.fromisoformat(ref.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                st.error("Acquisition time must be ISO format, e.g. 2026-10-25T09:30:00Z")
                st.stop()
            if not src.exists():
                st.error(f"Not found: {src}")
                st.stop()
            case = Case(case_name.strip() or "case", examiner)
            with st.status("Analysing evidence…", expanded=True) as status:
                bar = st.progress(0.0)

                def progress(msg, frac):
                    bar.progress(frac, text=msg)

                try:
                    result = run_analysis(src, case, AnalysisOptions(all_logs, reference, use_ml), progress)
                except Exception as exc:                       # show the error, keep it in the custody log
                    case.log("analysis_failed", error=repr(exc))
                    status.update(label="Analysis failed", state="error")
                    st.exception(exc)
                    st.stop()
                status.update(label=f"Done: {len(result.findings)} finding(s)", state="complete")
            set_result(result, case)
    else:
        saved = list_cases()
        if not saved:
            st.info(f"No finished cases in {paths['cases_dir']}")
        else:
            chosen = st.selectbox("Case", saved)
            if st.button("Open case", type="primary", use_container_width=True):
                result = load_case(chosen, examiner)
                set_result(result, Case(chosen, examiner))

    st.divider()
    st.caption(f"Evidence folder: `{paths['evidence_dir']}`  \nCases folder: `{paths['cases_dir']}`")
    for warning in onedrive_warnings(paths):
        st.warning(warning)


# ----------------------------------------------------------------------------- main area
result = st.session_state.get("result")
if result is None:
    st.header("Anti-Forensics Detector")
    st.markdown(
        "Analyses a Windows disk image, or exported `$MFT`, `.evtx`, registry hives and prefetch files, "
        "for signs that evidence was tampered with or destroyed.\n\n"
        "1. Enter the image or artifact folder in the sidebar and press **Run analysis**, "
        "or open a saved case.\n"
        "2. Review findings, the timeline and evidence hashes.\n"
        "3. Write your conclusion and generate the HTML/PDF report.\n\n"
        "| # | Module | Looks for |\n|---|---|---|\n"
        "| 1 | Timestomping | `$SI` earlier than `$FN`, whole-second dates, impossible dates |\n"
        "| 2 | Log wiping | Event 1102 / 104, missing record IDs, unexplained silence |\n"
        "| 3 | File wiping | SDelete-style renamed entries, zero / 0xFF filled content |\n"
        "| 4 | Free-space wiping | Uniform or random-looking unallocated space (image only) |\n"
        "| 5 | Hidden files | Alternate Data Streams, executables with the wrong extension |\n"
        "| 6 | Tool traces | CCleaner, SDelete, Eraser, timestomp tools in prefetch / registry / MFT |"
    )
    st.stop()

case: Case = st.session_state.case
findings = result.findings
counts = {lvl: sum(f.confidence.name == lvl for f in findings) for lvl in LEVELS}

st.header(f"Case: {result.case_name}")
st.caption(f"Input `{result.source}` · examiner {result.examiner} · analysed {result.finished_utc or result.started_utc}")

tab_over, tab_find, tab_time, tab_evid, tab_rep = st.tabs(
    ["Overview", "Findings", "Timeline", "Evidence & custody", "Report & export"])


def timeline_at(level: str):
    """Episodes rebuilt from findings at or above `level`. Filtering only the rows of the full
    timeline would keep episodes (and narratives) made of LOW findings: on a clean Windows
    install those are setup and update activity, tens of thousands of them."""
    return build_timeline([f for f in findings if f.confidence >= Confidence[level]])


overview_tl = timeline_at("MEDIUM")

# ----------------------------------------------------------------------------- Overview
with tab_over:
    c = st.columns(5)
    c[0].metric("HIGH", counts["HIGH"])
    c[1].metric("MEDIUM", counts["MEDIUM"])
    c[2].metric("LOW", counts["LOW"])
    c[3].metric("Episodes (MEDIUM+)", len(overview_tl.episodes))
    c[4].metric("Evidence files hashed", len(result.evidence))

    campaigns = [f for f in findings if f.module == "analysis"]
    for camp in campaigns:
        st.error(f"**{camp.title}**  \n" + " ".join(camp.reasons))

    st.subheader("Findings by module")
    if findings:
        df = findings_frame(findings).groupby(["Module", "Confidence"]).size().reset_index(name="Count")
        fig = px.bar(df, x="Count", y="Module", color="Confidence", orientation="h",
                     color_discrete_map=LEVEL_COLOURS, category_orders={"Confidence": LEVELS})
        fig.update_layout(height=60 + 45 * df["Module"].nunique(), margin=dict(l=0, r=0, t=10, b=0),
                          legend_title_text="", yaxis_title="")
        fig.update_xaxes(tickformat="d", rangemode="tozero")
        st.plotly_chart(fig, use_container_width=True)
    elif not any(m["status"] == "ran" and m["key"] != "ml_anomaly" for m in result.modules):
        # "0 findings" from analysing nothing must not look like a clean result
        msg = ("**Nothing was analysed:** every detector was skipped because the input contained "
               "no recognised artifacts (see *Modules* below).")
        if result.artifacts.get("unknown"):
            msg += (" If you gave a folder that contains a disk image, enter the image file's full "
                    "path instead (e.g. `...\\images\\clean_baseline.vhd`): images inside a folder "
                    "are not opened.")
        st.warning(msg)
    else:
        st.success("No findings. (This does not prove nothing happened; check which modules ran.)")

    st.subheader("Modules")
    if result.modules:
        st.dataframe(pd.DataFrame(result.modules)[["label", "status", "findings", "note"]]
                     .rename(columns=str.capitalize), hide_index=True, use_container_width=True,
                     column_config={"Note": st.column_config.TextColumn(width="large")})
    st.caption(f"Artifacts found: {result.artifacts}")

    st.subheader("Episodes (MEDIUM and HIGH findings)")
    if not overview_tl.episodes:
        st.write("No dated MEDIUM or HIGH findings.")
    for ep in overview_tl.episodes:
        lv = max((e.confidence for e in ep.entries), default=Confidence.LOW).name
        st.markdown(f"{badge(lv)} **Episode {ep.episode_id}**: {fmt_time(ep.start_time)} → "
                    f"{fmt_time(ep.end_time)} UTC, {ep.event_count} event(s). {ep.narrative}")

# ----------------------------------------------------------------------------- Findings
with tab_find:
    f1, f2, f3 = st.columns([2, 3, 3])
    levels = f1.multiselect("Confidence", LEVELS, default=["HIGH", "MEDIUM"])
    modules = sorted({f.module for f in findings})
    mods = f2.multiselect("Module", modules, default=modules)
    query = f3.text_input("Search title / path / artifact")
    q = query.lower().strip()
    shown = [f for f in findings if f.confidence.name in levels and f.module in mods
             and (not q or q in f"{f.title} {f.subject} {f.artifact}".lower())]
    st.caption(f"{len(shown)} of {len(findings)} finding(s)")

    if shown:
        frame = findings_frame(shown)
        st.dataframe(frame.style.map(lambda v: f"color: {LEVEL_COLOURS.get(v, '')}", subset=["Confidence"]),
                     hide_index=True, use_container_width=True, height=min(420, 38 + 35 * len(frame)))

        by_id = {f.id: f for f in shown}
        pick = st.selectbox("Finding details", list(by_id),
                            format_func=lambda i: f"{i} [{by_id[i].confidence.name}] {by_id[i].title}")
        f = by_id[pick]
        with st.container(border=True):
            st.markdown(f"{badge(f.confidence.name)} **{f.id} · {f.title}**")
            st.caption(f"{f.technique} · MITRE ATT&CK {f.mitre} · score {f.score}")
            st.markdown(f"**Subject:** `{f.subject}`  \n**Artifact:** `{f.artifact}`  \n"
                        f"**Time:** {fmt_time(f.event_time) + ' UTC' if f.event_time else 'not dated'}"
                        + (f" *({f.time_meaning})*" if f.time_meaning else ""))
            a, b = st.columns(2)
            with a:
                st.markdown("**Why it was flagged**")
                for r in f.reasons:
                    st.markdown(f"- {r}")
            with b:
                st.markdown("**Innocent explanations considered**")
                for n in f.benign_notes or ["(none recorded)"]:
                    st.markdown(f"- {n}")
            st.markdown("**Raw evidence**")
            st.json(f.evidence, expanded=True)

# ----------------------------------------------------------------------------- Timeline
with tab_time:
    min_level = st.select_slider("Show findings at or above", ["LOW", "MEDIUM", "HIGH"], value="MEDIUM")
    tl = timeline_at(min_level)
    entries = tl.entries
    if not entries:
        st.info("No dated findings at this level.")
    else:
        tdf = pd.DataFrame([{
            "Time": e.time, "Phase": e.phase, "Confidence": e.confidence.name, "ID": e.finding_id,
            "Finding": e.title, "Time meaning": e.time_meaning,
        } for e in entries])
        fig = px.scatter(tdf, x="Time", y="Phase", color="Confidence", symbol="Confidence",
                         hover_data={"ID": True, "Finding": True, "Time meaning": True, "Phase": False},
                         color_discrete_map=LEVEL_COLOURS, category_orders={"Confidence": LEVELS})
        fig.update_traces(marker=dict(size=13, line=dict(width=1, color="white")))
        fig.update_layout(height=360, margin=dict(l=0, r=0, t=10, b=0), xaxis_title="Time (UTC)",
                          yaxis_title="", legend_title_text="")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Each time is what its artifact records; *Time meaning* says what it stands for "
                   "(e.g. prefetch last run, $SI 'MFT changed', event logged).")

        for ep in tl.episodes:
            with st.expander(f"Episode {ep.episode_id}: {fmt_time(ep.start_time)} → {fmt_time(ep.end_time)} UTC "
                             f"({ep.duration_minutes():.1f} min)", expanded=ep.episode_id == 1):
                for e in ep.entries:
                    st.markdown(f"`{e.time:%H:%M:%S}` {badge(e.confidence.name)} **{e.phase}**: {e.title}  "
                                f":gray[({e.finding_id}; {e.time_meaning})]")
                st.caption(ep.narrative)

    undated = tl.undated_findings
    if undated:
        st.subheader("Undated findings")
        st.dataframe(findings_frame(undated)[["ID", "Confidence", "Finding", "Artifact"]],
                     hide_index=True, use_container_width=True)

# ----------------------------------------------------------------------------- Evidence & custody
with tab_evid:
    st.subheader("Evidence hashes")
    st.caption("Computed when each file was loaded. Compare the disk image's hash with FTK Imager's .txt log.")
    if result.evidence:
        st.dataframe(pd.DataFrame(result.evidence)[["path", "source", "size", "md5", "sha256"]],
                     hide_index=True, use_container_width=True)
    src = Path(result.source)
    if src.is_file() and src.suffix.lower() in IMAGE_EXTENSIONS:
        st.caption("The hash above is of the image *file*. FTK Imager's .txt log holds the hash of the "
                   "*disk data* inside it; compute that here to compare.")
        if st.button("Compute media hash (compare with FTK Imager)"):
            with st.spinner("Hashing the disk data inside the image (several minutes for large images)…"):
                mh = media_hash(src)
            case.log("media_hash", image=str(src), **mh)
            st.session_state.media_hash = mh
        if st.session_state.get("media_hash"):
            mh = st.session_state.media_hash
            st.code(f"MD5     {mh['md5']}\nSHA-256 {mh['sha256']}\nsize    {mh['media_size']:,} bytes")

    if st.button("Re-verify evidence hashes"):
        case.evidence = list(result.evidence)
        with st.spinner("Re-hashing…"):
            try:
                st.session_state.verification = case.verify_evidence()
            except FileNotFoundError as exc:
                st.error(f"Evidence file missing: {exc.filename}")
    ver = st.session_state.get("verification")
    if ver:
        bad = [v for v in ver if not v["match"]]
        if bad:
            st.error(f"{len(bad)} file(s) no longer match their recorded SHA-256!")
        else:
            st.success(f"All {len(ver)} file(s) still match their recorded SHA-256.")
        st.dataframe(pd.DataFrame(ver), hide_index=True, use_container_width=True)

    st.subheader("Chain-of-custody log")
    log = case.read_log()
    st.caption(f"{case.log_file} · {len(log)} entr{'y' if len(log) == 1 else 'ies'} · append-only")
    if log:
        ldf = pd.DataFrame(log)
        first = [c for c in ("time_utc", "examiner", "action") if c in ldf]
        ldf["details"] = [json.dumps({k: v for k, v in row.items() if k not in first + ["host"] and pd.notna(v)},
                                     default=str) for row in log]
        st.dataframe(ldf[first + ["details"]].iloc[::-1], hide_index=True, use_container_width=True, height=360)

# ----------------------------------------------------------------------------- Report & export
with tab_rep:
    st.subheader("Forensic report")
    a, b = st.columns([1, 2])
    rep_level = a.selectbox("List findings at or above", ["MEDIUM", "HIGH", "LOW"],
                            help="Lower findings are still counted in the report and kept in the CSV/JSON.")
    b.info("The examiner writes the conclusion. The tool does not fill it in; "
           "if left empty the report shows a placeholder.")
    conclusion = st.text_area("Examiner's conclusion", height=160,
                              placeholder="Your own interpretation of the findings and timeline…")
    if st.session_state.get("verification") is None:
        st.caption("Tip: press *Re-verify evidence hashes* on the Evidence tab first so the report includes it.")

    if st.button("Generate HTML + PDF report", type="primary"):
        with st.spinner("Writing report…"):
            st.session_state.reports = write_reports(
                result, case, Confidence[rep_level], conclusion, st.session_state.get("verification"))
        st.success(f"Written to {case.dir}")

    reports = st.session_state.get("reports")
    if reports:
        cols = st.columns(4)
        mime = {"html": "text/html", "pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}
        for col, (kind, path) in zip(cols, reports.items()):
            col.download_button(f"Download {path.name}", path.read_bytes(), file_name=path.name,
                                mime=mime[kind], use_container_width=True)

    st.subheader("Quick export (all findings)")
    e1, e2 = st.columns(2)
    e1.download_button("findings.csv", findings_to_csv(findings), file_name=f"{result.case_name}_findings.csv",
                       mime="text/csv", use_container_width=True)
    e2.download_button("analysis.json", result_to_json(result), file_name=f"{result.case_name}_analysis.json",
                       mime="application/json", use_container_width=True)
