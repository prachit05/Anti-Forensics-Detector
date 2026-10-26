"""Anti-forensic tool traces detector (MITRE ATT&CK T1070, T1562).

Forensic concept
----------------
When attackers or rogue insiders attempt to cover their tracks, they deploy anti-forensic
tools to wipe files, zero free space, clear event logs, or manipulate timestamps.
Even if the perpetrator subsequently deletes the anti-forensic tool itself, Windows
silently logs execution evidence across multiple independent forensic artifacts:

1. Windows Prefetch (.pf files):
   - Records executable name, run count, and the last 8 execution timestamps (Win10/11).
   - Even if the executable was deleted, its prefetch file persists in C:\\Windows\\Prefetch.
2. Windows Registry - UserAssist (NTUSER.DAT):
   - Records GUI program launches in ROT-13 encoded format, along with run counts and
     last run timestamps. Persists even if prefetch is disabled or cleared.
3. Windows Registry - Uninstall Keys (SOFTWARE):
   - Proves that a wiping utility (e.g. CCleaner, Eraser, BleachBit) was formally installed
     on the endpoint, recording installation timestamps and install paths.
4. Windows Registry - RunMRU (NTUSER.DAT):
   - Records manual command execution in the Windows 'Run' dialog (e.g. 'sdelete -z',
     'wevtutil cl Security').
5. MFT File System ($MFT):
   - Residual binaries, configuration files (e.g. ccleaner.ini), or installation folders.

Known tool signatures detected:
  - SDelete (Sysinternals free-space and file wiper)
  - CCleaner (Piriform system cleaner and free-space wiper)
  - Eraser (Secure file deletion utility)
  - BleachBit (Open-source system wiper)
  - Timestomp / NewFileTime / AttributeChanger (timestamp editors)
  - Wevtutil (command-line Windows event log clearing)
  - Cipher (built-in disk free-space wiping pass)

Built-in Windows tools (wevtutil, cipher)
-----------------------------------------
Windows itself runs wevtutil during setup and updates (to register event-log manifests),
and both tools ship in System32 and WinSxS on every install. So running one is reported
as LOW on its own, and copies under \\Windows\\ are not reported at all. A run becomes
MEDIUM when the Stage 5 correlation finds the matching action (a log clear, a wipe)
nearby. A command typed by a user in the Run dialog is still reported in full.

Honest limits
-------------
- Tools like CCleaner or BleachBit are widely used for legitimate system maintenance.
  Detecting their presence or execution does not inherently prove criminal intent,
  which is why findings describe the *tool capability* and feed into the Stage 5
  unified timeline to determine whether wiping coincided with suspicious activity.
- Portable command-line tools executed via memory injection or living-off-the-land
  without disk writes or prefetch will not appear here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PureWindowsPath

import pandas as pd

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.filetime import filetime_to_datetime

DEFAULT_CONFIG = {
    "medium_at": 4,
    "high_at": 6,
    "weights": {
        "prefetch_executed": 6,
        "userassist_executed": 6,
        "registry_installed": 4,
        "run_mru_command": 4,
        "mft_file_present": 2,
    },
    # Built-in Windows tools (wevtutil, cipher) ship on every system and are also run by
    # Windows itself, installers and admin scripts. Their presence under \Windows\ is not
    # reported, and an execution trace scores this much lower than for a third-party wiper:
    # 6 - 4 = 2 (LOW). On the clean test image Windows ran wevtutil 4 times during setup.
    "builtin_tool_discount": 4,
    "builtin_system_prefix": "\\windows\\",
    "known_tools": {
        "sdelete": {
            "names": ["sdelete.exe", "sdelete64.exe"],
            "category": "Secure Deletion / Free Space Wiper",
            "description": "Sysinternals SDelete secure file deletion and free-space wiper",
            "mitre": "T1070.004",
        },
        "ccleaner": {
            "names": ["ccleaner.exe", "ccleaner64.exe"],
            "category": "System Cleaner / Wiper",
            "description": "Piriform CCleaner artifact and free-space wiper",
            "mitre": "T1070",
        },
        "eraser": {
            "names": ["eraser.exe"],
            "category": "Secure Deletion",
            "description": "Eraser secure file and free-space deletion utility",
            "mitre": "T1070.004",
        },
        "bleachbit": {
            "names": ["bleachbit.exe", "bleachbit_console.exe"],
            "category": "System Cleaner / Wiper",
            "description": "BleachBit system cleaner and wiper",
            "mitre": "T1070",
        },
        "timestomp": {
            "names": [
                "timestomp.exe",
                "newfiletime.exe",
                "newfiletime_x64.exe",
                "setmace.exe",
                "attributechanger.exe",
            ],
            "category": "Timestomping Utility",
            "description": "File timestamp modification tool",
            "mitre": "T1070.006",
        },
        "wevtutil": {
            "names": ["wevtutil.exe"],
            "category": "Log Manipulation",
            "description": "Windows command-line event log utility",
            "mitre": "T1070.001",
            "builtin": True,
        },
        "cipher": {
            "names": ["cipher.exe"],
            "category": "Disk Wiper",
            "description": "Windows built-in encryption and free-space wiping utility (cipher /w)",
            "mitre": "T1070.004",
            "builtin": True,
        },
    },
}


def _match_tool_name(test_name: str, known_tools: dict) -> tuple[str, dict] | None:
    """Check if an executable name matches known anti-forensic tools."""
    name_lower = PureWindowsPath(test_name).name.lower()
    for tool_id, tool_info in known_tools.items():
        if any(name_lower == target.lower() for target in tool_info.get("names", [])):
            return tool_id, tool_info
        if tool_id in name_lower and any(name_lower.endswith(ext) for ext in (".exe", ".pf")):
            return tool_id, tool_info
    return None


def _builtin_note(tool_info: dict, cfg: dict) -> str:
    """Extra benign note for built-in Windows tools ('' for third-party tools)."""
    if not tool_info.get("builtin"):
        return ""
    return ("Built-in Windows tool: Windows itself runs it during setup and updates (e.g. to register "
            "event-log manifests), as do installers and admin scripts, so the score is lowered by "
            f"{cfg['builtin_tool_discount']}. It matters when the matching action (a log clear or a "
            "wipe) is found nearby; check the command line (RunMRU, Event 4688) if available.")


def detect_prefetch(prefetch_df: pd.DataFrame, known_tools: dict, weights: dict, cfg: dict) -> list[Finding]:
    """Inspect prefetch execution records for anti-forensic tools."""
    findings = []
    if prefetch_df.empty:
        return findings

    # Filter to most recent execution per prefetch file (run_index == 0)
    recent_runs = prefetch_df[prefetch_df["run_index"] == 0]

    for _, row in recent_runs.iterrows():
        exe = str(row.get("exe_name", ""))
        match = _match_tool_name(exe, known_tools)
        if not match:
            # Also check pf_file name
            match = _match_tool_name(str(row.get("pf_file", "")), known_tools)
        if not match:
            continue

        tool_id, tool_info = match
        builtin = bool(tool_info.get("builtin"))
        score = weights["prefetch_executed"]
        builtin_note = _builtin_note(tool_info, cfg)
        if builtin_note:
            score -= cfg["builtin_tool_discount"]
        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        run_time = row.get("run_time")
        run_dt = run_time.to_pydatetime() if hasattr(run_time, "to_pydatetime") else (
            run_time if isinstance(run_time, datetime) else None
        )
        if run_dt and run_dt.tzinfo is None:
            run_dt = run_dt.replace(tzinfo=timezone.utc)

        findings.append(Finding(
            module="tool_traces",
            technique=f"Anti-Forensic Tool Execution: {tool_info['category']}",
            mitre=tool_info.get("mitre", "T1070"),
            title=f"Anti-forensic tool executed: {exe} ({tool_info['description']})",
            confidence=confidence,
            score=score,
            subject=exe,
            artifact=f"Prefetch: {row.get('pf_file')}",
            reasons=[
                f"Prefetch file '{row.get('pf_file')}' confirms execution of {exe}.",
                f"Recorded total run count: {row.get('run_count')}.",
            ],
            benign_notes=[
                "Legitimate users and administrators also run cleaning tools for routine "
                "maintenance; execution shows capability, not intent."
            ] + ([builtin_note] if builtin_note else []),
            evidence={
                "builtin_windows_tool": builtin,
                "exe_name": exe,
                "pf_file": str(row.get("pf_file")),
                "run_count": int(row.get("run_count", 0)),
                "last_run": run_dt.isoformat() if run_dt else None,
            },
            event_time=run_dt,
            time_meaning="last recorded execution time in prefetch",
        ))

    return findings


def detect_registry(registry_data: dict, known_tools: dict, weights: dict, cfg: dict) -> list[Finding]:
    """Inspect UserAssist, Installed Programs, and RunMRU registry records."""
    findings = []

    # 1. UserAssist
    for ua in registry_data.get("userassist", []):
        match = _match_tool_name(ua.path, known_tools)
        if not match:
            continue
        tool_id, tool_info = match
        score = weights["userassist_executed"]
        builtin_note = _builtin_note(tool_info, cfg)
        if builtin_note:
            score -= cfg["builtin_tool_discount"]
        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        findings.append(Finding(
            module="tool_traces",
            technique=f"UserAssist Execution Trace: {tool_info['category']}",
            mitre=tool_info.get("mitre", "T1070"),
            title=f"UserAssist execution trace: {PureWindowsPath(ua.path).name} (User: {ua.user or 'Current'})",
            confidence=confidence,
            score=score,
            subject=ua.path,
            artifact=f"Registry NTUSER.DAT UserAssist ({ua.guid})",
            reasons=[
                f"NTUSER.DAT UserAssist records GUI execution of '{ua.path}'.",
                f"Recorded run count: {ua.run_count}.",
            ],
            benign_notes=["User may have launched tool for general cleaning or privacy purposes."]
            + ([builtin_note] if builtin_note else []),
            evidence={
                "program_path": ua.path,
                "run_count": ua.run_count,
                "user": ua.user,
                "last_run": ua.last_run.isoformat() if ua.last_run else None,
            },
            event_time=ua.last_run,
            time_meaning="UserAssist last execution time",
        ))

    # 2. Installed Programs / Uninstall Keys
    for app in registry_data.get("installed_programs", []):
        combined = f"{app.display_name} {app.key_name}".lower()
        match = None
        for tool_id, tool_info in known_tools.items():
            if tool_id in combined or any(n.replace(".exe", "") in combined for n in tool_info.get("names", [])):
                match = (tool_id, tool_info)
                break
        if not match:
            continue

        tool_id, tool_info = match
        score = weights["registry_installed"]
        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        findings.append(Finding(
            module="tool_traces",
            technique=f"Installed Anti-Forensic Software: {tool_info['category']}",
            mitre=tool_info.get("mitre", "T1070"),
            title=f"Installed anti-forensic software: {app.display_name}",
            confidence=confidence,
            score=score,
            subject=app.display_name,
            artifact=f"Registry SOFTWARE Uninstall key: {app.key_name}",
            reasons=[
                f"Software '{app.display_name}' was installed on the system.",
                f"Publisher: {app.publisher or 'Unknown'}, Version: {app.display_version or 'N/A'}.",
            ],
            benign_notes=["Installation alone does not prove the software was used during the incident."],
            evidence={
                "display_name": app.display_name,
                "display_version": app.display_version,
                "install_location": app.install_location,
                "install_date": app.install_date,
            },
            event_time=app.last_written,
            time_meaning="Uninstall registry key last written",
        ))

    # 3. RunMRU Commands
    for mru in registry_data.get("run_mru", []):
        cmd_lower = mru.command.lower()
        match = None
        for tool_id, tool_info in known_tools.items():
            if tool_id in cmd_lower or any(n in cmd_lower for n in tool_info.get("names", [])):
                match = (tool_id, tool_info)
                break
        if not match:
            continue

        tool_id, tool_info = match
        score = weights["run_mru_command"]
        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        findings.append(Finding(
            module="tool_traces",
            technique=f"RunMRU Command Trace: {tool_info['category']}",
            mitre=tool_info.get("mitre", "T1070"),
            title=f"RunMRU command typed by user: '{mru.command}'",
            confidence=confidence,
            score=score,
            subject=mru.command,
            artifact="Registry NTUSER.DAT RunMRU",
            reasons=[
                f"User typed anti-forensic command '{mru.command}' into the Windows Run dialog.",
            ],
            benign_notes=["Command execution in RunMRU confirms user intent to execute."],
            evidence={
                "command": mru.command,
                "order": mru.order,
                "user": mru.user,
            },
            event_time=mru.last_written,
            time_meaning="RunMRU key modification time",
        ))

    return findings


def detect_mft(mft: pd.DataFrame, known_tools: dict, weights: dict, cfg: dict) -> list[Finding]:
    """Inspect MFT file paths for anti-forensic tool binaries or directories."""
    findings = []
    if mft.empty:
        return findings

    all_names = {n.lower() for info in known_tools.values() for n in info.get("names", [])}
    df = mft[(mft["entry"] >= 24) & mft["name"].fillna("").str.lower().isin(all_names)]
    for _, row in df.iterrows():
        name = str(row.get("name", "")).lower()
        path = str(row.get("path", "")).lower()
        if not name:
            continue

        match = None
        for tool_id, tool_info in known_tools.items():
            if name in tool_info.get("names", []):
                match = (tool_id, tool_info)
                break
        if not match:
            continue

        tool_id, tool_info = match
        if tool_info.get("builtin") and path.startswith(cfg["builtin_system_prefix"]):
            continue    # the normal Windows copy of a built-in tool: present on every system
        score = weights["mft_file_present"]
        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        raw_mod = int(row.get("si_modified", 0)) or int(row.get("si_created", 0))
        event_time = filetime_to_datetime(raw_mod) if raw_mod > 0 else None

        findings.append(Finding(
            module="tool_traces",
            technique=f"Tool Binary Present: {tool_info['category']}",
            mitre=tool_info.get("mitre", "T1070"),
            title=f"Anti-forensic binary located on disk: {row['name']}",
            confidence=confidence,
            score=score,
            subject=str(row["path"]),
            artifact=f"$MFT entry {row['entry']}",
            reasons=[
                f"Binary '{row['name']}' ({tool_info['description']}) was located at '{row['path']}'.",
            ],
            benign_notes=["The file may have been downloaded or installed without being executed."],
            evidence={"entry": int(row["entry"]), "path": str(row["path"]), "name": str(row["name"])},
            event_time=event_time,
            time_meaning="file modified timestamp",
        ))

    return findings


def detect(
    prefetch_df: pd.DataFrame | None = None,
    registry_data: dict | None = None,
    mft: pd.DataFrame | None = None,
    cfg: dict | None = None,
) -> list[Finding]:
    """Scan prefetch, registry, and MFT for traces of known anti-forensic tools.

    Parameters:
        prefetch_df: DataFrame from prefetch_parser.load_prefetch_dir()
        registry_data: dict from registry_parser.load_registry_artifacts()
        mft: DataFrame from mft_parser.load_mft()
        cfg: optional configuration overrides
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("tool_traces"), cfg or {})
    known_tools = cfg.get("known_tools", DEFAULT_CONFIG["known_tools"])
    weights = cfg.get("weights", DEFAULT_CONFIG["weights"])

    findings: list[Finding] = []

    if prefetch_df is not None and not prefetch_df.empty:
        findings.extend(detect_prefetch(prefetch_df, known_tools, weights, cfg))

    if registry_data is not None:
        findings.extend(detect_registry(registry_data, known_tools, weights, cfg))

    if mft is not None and not mft.empty:
        findings.extend(detect_mft(mft, known_tools, weights, cfg))

    return assign_ids(sort_findings(findings))
