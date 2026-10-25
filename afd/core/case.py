"""Case folder, evidence hashing and chain-of-custody log.

Forensic concept
----------------
Integrity: an examiner must show the evidence was not changed during analysis.
We hash every input with MD5 and SHA-256 when it is loaded. Re-hashing later and
getting the same values shows the data is unchanged.

Chain of custody: a record of who did what to the evidence, and when. Every action
(evidence added, artifact extracted, parser run) is appended to a JSON Lines file.
The file is only ever appended to, never rewritten.
"""
import getpass
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from afd.core.config import get_paths

CHUNK = 4 * 1024 * 1024  # read evidence in 4 MB pieces so multi-GB images fit in memory


def hash_file(path: Path) -> dict:
    """Return MD5 and SHA-256 of a file, reading it read-only in chunks."""
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


class Case:
    """One investigation: a folder under cases_dir with a custody log and outputs."""

    def __init__(self, name: str, examiner: str | None = None):
        self.name = name
        self.examiner = examiner or getpass.getuser()
        self.dir = get_paths()["cases_dir"] / name
        self.extracted_dir = self.dir / "extracted"   # artifacts pulled out of a disk image
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.dir / "custody_log.jsonl"
        self.evidence: list[dict] = []

    def log(self, action: str, **details) -> None:
        """Append one chain-of-custody entry (UTC time, examiner, host, action)."""
        entry = {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner,
            "host": platform.node(),
            "action": action,
            **details,
        }
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    def add_evidence(self, path: Path, source: str = "input") -> dict:
        """Hash an evidence file, record it, and log the action."""
        path = Path(path)
        record = {"path": str(path), "size": path.stat().st_size, "source": source,
                  **hash_file(path)}
        self.evidence.append(record)
        self.log("evidence_hashed", **record)
        return record

    def read_log(self) -> list[dict]:
        """Return every custody-log entry, oldest first."""
        if not self.log_file.exists():
            return []
        with open(self.log_file, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def load_evidence_from_log(self) -> list[dict]:
        """Rebuild self.evidence from the custody log (used when a saved case is reopened)."""
        keys = ("path", "size", "source", "md5", "sha256")
        seen = {}
        for entry in self.read_log():
            if entry.get("action") == "evidence_hashed":
                seen[entry["path"]] = {k: entry.get(k) for k in keys}
        self.evidence = list(seen.values())
        return self.evidence

    def verify_evidence(self) -> list[dict]:
        """Re-hash every recorded file and report whether it still matches."""
        results = []
        for rec in self.evidence:
            now = hash_file(Path(rec["path"]))
            ok = now["sha256"] == rec["sha256"]
            results.append({"path": rec["path"], "match": ok})
            self.log("evidence_verified", path=rec["path"], match=ok)
        return results
