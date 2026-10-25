"""PDF report built with reportlab (pure Python, no GTK or browser needed on Windows).

It has the same sections as the HTML report, built from the same context dict.
"""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

LEVEL_COLOURS = {"HIGH": colors.HexColor("#b3261e"), "MEDIUM": colors.HexColor("#b26a00"),
                 "LOW": colors.HexColor("#3a6ea5")}
GRID = colors.HexColor("#d5dbe0")
HEAD_BG = colors.HexColor("#f5f7f9")

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontSize=16, spaceAfter=2)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=4)
H3 = ParagraphStyle("h3", parent=_ss["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2)
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontSize=9, leading=11.5)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.5, leading=9.5)
MONO = ParagraphStyle("mono", parent=SMALL, fontName="Courier")
MUTED = ParagraphStyle("muted", parent=SMALL, textColor=colors.HexColor("#5b6670"))
NOTICE = ParagraphStyle("notice", parent=BODY, backColor=colors.HexColor("#fff4e5"), borderPadding=4)


def _p(text, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")).replace("\n", "<br/>"), style)


def _badge(level: str) -> str:
    colour = LEVEL_COLOURS.get(level, colors.grey).hexval()[2:]
    return f'<font color="#{colour}"><b>{level}</b></font>'


def _table(rows, widths, header=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), HEAD_BG))
    t.setStyle(TableStyle(style))
    return t


def _hdr(*names) -> list:
    return [Paragraph(f"<b>{escape(n)}</b>", SMALL) for n in names]


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 8 * mm, doc.title)
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf(context: dict, out_path: Path) -> Path:
    out_path = Path(out_path)
    W = A4[0] - 30 * mm                      # usable width
    doc = SimpleDocTemplate(str(out_path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm, title=context["title"],
                            author=context["examiner"])
    s: list = [_p(context["title"], H1),
               _p(f"Generated {context['generated']} by Anti-Forensics Detector v{context['tool_version']}", MUTED)]

    # 1. Case details
    s.append(_p("1. Case details", H2))
    rows = [("Case", context["case_name"]), ("Examiner", context["examiner"]),
            ("Input examined", context["source"]),
            ("Analysis started / finished", f"{context['started']} / {context['finished']}"),
            ("Options", context["options"]), ("Artifacts found", context["artifacts"])]
    s.append(_table([[_p(k, SMALL), _p(v, MONO)] for k, v in rows], [0.28 * W, 0.72 * W], header=False))

    # 2. Evidence integrity
    s.append(_p("2. Evidence integrity", H2))
    rows = [_hdr("File", "Size (bytes)", "MD5 / SHA-256")]
    for e in context["evidence"]:
        rows.append([_p(f"{e['path']}\n{e.get('source', '')}", MONO), _p(f"{e.get('size') or 0:,}", SMALL),
                     _p(f"{e.get('md5')}\n{e.get('sha256')}", MONO)])
    if len(rows) == 1:
        rows.append([_p("No evidence records in the custody log.", MUTED), "", ""])
    s.append(_table(rows, [0.36 * W, 0.12 * W, 0.52 * W]))
    if context["verification"] is not None:
        rows = [_hdr("File", "Re-verification")]
        for v in context["verification"]:
            res = '<font color="#1e7d32"><b>SHA-256 matches</b></font>' if v["match"] else \
                  '<font color="#b3261e"><b>MISMATCH</b></font>'
            rows.append([_p(v["path"], MONO), Paragraph(res, SMALL)])
        s.append(_table(rows, [0.75 * W, 0.25 * W]))
    else:
        s.append(_p("Evidence was not re-hashed before this report was generated.", MUTED))

    # 3. Method
    s.append(_p("3. Method", H2))
    rows = [_hdr("Module", "Status", "Findings", "Note")]
    for m in context["modules"]:
        rows.append([_p(m["label"], SMALL), _p(m["status"], SMALL),
                     _p(m["findings"] if m["status"] == "ran" else "", SMALL), _p(m.get("note", ""), SMALL)])
    s.append(_table(rows, [0.32 * W, 0.11 * W, 0.11 * W, 0.46 * W]))
    s.append(_p("Confidence states how likely it is that the action happened, not who did it or why.", MUTED))

    # 4. Summary
    s.append(_p("4. Summary of results", H2))
    s.append(Paragraph("   ".join(f"{_badge(k)}: {v}" for k, v in context["counts"].items()), BODY))
    for line in context["auto_summary"]:
        s.append(_p(f"• {line}"))
    rows = [_hdr("Module", "HIGH", "MEDIUM", "LOW")]
    for mod, c in context["module_counts"].items():
        rows.append([_p(mod, SMALL)] + [_p(c.get(k, 0), SMALL) for k in ("HIGH", "MEDIUM", "LOW")])
    s.append(_table(rows, [0.4 * W, 0.2 * W, 0.2 * W, 0.2 * W]))

    # 5. Timeline
    s.append(_p("5. Timeline", H2))
    s.append(_p(f"Findings at {context['min_confidence']} or above, in time order (UTC). "
                "Events less than 30 minutes apart form one episode.", MUTED))
    for ep in context["episodes"]:
        s.append(_p(f"Episode {ep['id']}: {ep['start']} to {ep['end']} ({ep['duration']})", H3))
        rows = [_hdr("Time", "ID", "Conf.", "Phase", "Finding", "Time meaning")]
        for e in ep["entries"]:
            rows.append([_p(e["time"], MONO), _p(e["id"], MONO), Paragraph(_badge(e["confidence"]), SMALL),
                         _p(e["phase"], SMALL), _p(e["title"], SMALL), _p(e["time_meaning"], MUTED)])
        s.append(_table(rows, [0.1 * W, 0.1 * W, 0.1 * W, 0.15 * W, 0.37 * W, 0.18 * W]))
        s.append(_p(f"Tool summary: {ep['narrative']}", MUTED))
    if not context["episodes"]:
        s.append(_p("No dated findings at this level.", MUTED))
    if context["undated"]:
        s.append(_p("Undated findings", H3))
        rows = [_hdr("ID", "Conf.", "Finding", "Artifact")]
        for u in context["undated"]:
            rows.append([_p(u["id"], MONO), Paragraph(_badge(u["confidence"]), SMALL),
                         _p(u["title"], SMALL), _p(u["artifact"], MONO)])
        s.append(_table(rows, [0.1 * W, 0.1 * W, 0.5 * W, 0.3 * W]))

    # 6. Findings
    s.append(_p("6. Findings", H2))
    note = f"Listing findings at {context['min_confidence']} or above."
    if context["omitted"]:
        note += f" {context['omitted']} lower-confidence finding(s) are in findings.csv / findings.json."
    s.append(_p(note, MUTED))
    for f in context["findings"]:
        block = [Paragraph(f"{_badge(f['confidence'])} <b>{escape(f['id'])}</b> {escape(f['title'])}", H3),
                 _p(f"{f['technique']} · MITRE ATT&CK {f['mitre']} · score {f['score']}", MUTED),
                 _p(f"Subject: {f['subject']}", SMALL), _p(f"Artifact: {f['artifact']}", SMALL),
                 _p(f"Time: {f['time_text'] or 'not dated'}"
                    + (f" ({f['time_meaning']})" if f["time_meaning"] else ""), SMALL),
                 Paragraph("<b>Why it was flagged</b>", SMALL)]
        block += [_p(f"• {r}", SMALL) for r in f["reasons"]]
        if f["benign_notes"]:
            block.append(Paragraph("<b>Innocent explanations considered</b>", SMALL))
            block += [_p(f"• {n}", SMALL) for n in f["benign_notes"]]
        if f["evidence_rows"]:
            block.append(_table([[_p(k, SMALL), _p(v, MONO)] for k, v in f["evidence_rows"]],
                                [0.28 * W, 0.72 * W], header=False))
        block.append(Spacer(1, 4))
        s.append(KeepTogether(block))
    if not context["findings"]:
        s.append(_p("No findings at this level.", MUTED))

    # 7-8. Conclusion and limitations
    s.append(_p("7. Conclusion (examiner)", H2))
    s.append(_p(context["conclusion"], NOTICE if context["conclusion_missing"] else BODY))
    s.append(_p("8. Limitations of the method", H2))
    s += [_p(f"• {l}") for l in context["limitations"]]

    # Appendix
    s.append(_p("Appendix: chain-of-custody log", H2))
    rows = [_hdr("Time (UTC)", "Examiner", "Action", "Details")]
    for e in context["custody_log"]:
        details = " ".join(f"{k}={v}" for k, v in e.items() if k not in ("time_utc", "examiner", "action", "host"))
        rows.append([_p(e.get("time_utc", ""), MONO), _p(e.get("examiner", ""), SMALL),
                     _p(e.get("action", ""), SMALL), _p(details, MONO)])
    s.append(_table(rows, [0.22 * W, 0.12 * W, 0.17 * W, 0.49 * W]))

    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return out_path
