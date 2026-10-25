"""Windows event log (.evtx) parser.

Forensic concept
----------------
An .evtx file is a 4 KB file header followed by 64 KB "chunks" of binary-XML records.
Each record has:
  * EventRecordID - a counter that goes up by 1 for every event written to that log.
    It never resets during normal use, so a jump (e.g. 1500 -> 1900) means records
    are missing. That is the "record number gap" check in Stage 3.
  * TimeCreated   - when the event happened (UTC).
  * EventID + Provider - what happened. Key ones for anti-forensics:
        1102 (Microsoft-Windows-Eventlog, Security log)  "The audit log was cleared"
        104  (Microsoft-Windows-Eventlog, System log)    "The <X> log file was cleared"
    Clearing a log writes this event as the first record of the new, empty log, and
    it names the account that did it.

The file header also stores the oldest and next record numbers, plus a "dirty" flag
(set when the file was not closed cleanly). These are compared with the records
actually present.
"""
from pathlib import Path
from xml.etree import ElementTree as ET

import pandas as pd
from Evtx.Evtx import Evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_record_xml(xml: str) -> dict:
    """Pull the fields we need out of one record's XML."""
    root = ET.fromstring(xml)
    sys = root.find("e:System", NS)

    def text(tag):
        el = sys.find(f"e:{tag}", NS)
        return el.text if el is not None else None

    provider = sys.find("e:Provider", NS)
    created = sys.find("e:TimeCreated", NS)
    security = sys.find("e:Security", NS)
    row = {
        "record_id": int(text("EventRecordID")),
        "time_created": created.get("SystemTime") if created is not None else None,
        "event_id": int(text("EventID")),
        "provider": provider.get("Name") if provider is not None else None,
        "channel": text("Channel"),
        "computer": text("Computer"),
        "level": text("Level"),
        "user_sid": security.get("UserID") if security is not None else None,
    }

    # EventData holds <Data Name="...">value</Data> pairs.
    # UserData (used by 1102/104) holds free-form child elements, so we flatten both.
    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for i, d in enumerate(ed):
            data[d.get("Name") or f"Data{i}"] = d.text
    ud = root.find("e:UserData", NS)
    if ud is not None:
        for child in ud.iter():
            if len(child) == 0 and child.text and child.text.strip():
                data[child.tag.split("}")[-1]] = child.text.strip()
    row["data"] = data
    return row


def read_header(path: Path) -> dict:
    """File-header facts used by the log-wiping checks."""
    with Evtx(str(path)) as log:
        h = log.get_file_header()
        return {
            "oldest_chunk": h.oldest_chunk(),
            "current_chunk": h.current_chunk_number(),
            "next_record_number": h.next_record_number(),
            "is_dirty": h.is_dirty(),
            "is_full": h.is_full(),
        }


def load_evtx(path: Path, max_records: int | None = None) -> tuple[pd.DataFrame, dict]:
    """Parse an .evtx file. Returns (records DataFrame, info dict).

    Records that fail to parse are counted, not fatal: corrupted records are
    themselves a possible sign of tampering.
    """
    path = Path(path)
    rows, errors = [], 0
    with Evtx(str(path)) as log:
        for i, record in enumerate(log.records()):
            if max_records and i >= max_records:
                break
            try:
                rows.append(_parse_record_xml(record.xml()))
            except Exception:
                errors += 1

    df = pd.DataFrame(rows, columns=["record_id", "time_created", "event_id", "provider",
                                     "channel", "computer", "level", "user_sid", "data"])
    df["time_created"] = pd.to_datetime(df["time_created"], utc=True, errors="coerce")
    df = df.sort_values("record_id").reset_index(drop=True)
    df["log_file"] = path.name

    info = {"file": path.name, "records": len(df), "parse_errors": errors}
    try:
        info.update(read_header(path))
    except Exception as exc:          # a damaged header is itself worth reporting
        info["header_error"] = str(exc)
    return df, info
