"""CSV and JSON export of every finding (all confidence levels, unlike the report).

CSV is for spreadsheets and for comparing with Autopsy's output; JSON keeps the full
structure (nested evidence, timeline episodes) for other tools.
"""
from __future__ import annotations

import csv
import io
import json

CSV_COLUMNS = ["id", "confidence", "score", "module", "technique", "mitre", "title", "subject",
               "artifact", "event_time", "time_meaning", "reasons", "benign_notes", "evidence"]


def findings_to_csv(findings) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for f in findings:
        d = f.to_dict()
        d["reasons"] = " | ".join(d["reasons"])
        d["benign_notes"] = " | ".join(d["benign_notes"])
        d["evidence"] = json.dumps(d["evidence"], default=str)
        writer.writerow({k: d.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue()


def result_to_json(result) -> str:
    """Everything about one analysis run in one JSON document."""
    return json.dumps({
        "summary": result.summary_dict(),
        "evidence": result.evidence,
        "findings": [f.to_dict() for f in result.findings],
        "timeline": result.timeline.to_dict(),
    }, indent=2, default=str)
