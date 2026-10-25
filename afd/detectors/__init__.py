"""Anti-Forensics Detectors package."""
from afd.detectors import (
    file_wiping,
    freespace,
    hidden_files,
    log_wiping,
    timestomp,
    tool_traces,
)

__all__ = [
    "timestomp",
    "log_wiping",
    "file_wiping",
    "freespace",
    "hidden_files",
    "tool_traces",
]
