"""Windows Registry hive parser using python-registry.

Forensic concept
----------------
Windows Registry hives are binary files (regf) that store OS and application configuration.
Key anti-forensic evidence lives across two primary hives:

1. NTUSER.DAT (per-user profile):
   - UserAssist:
     Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count
     Windows tracks GUI program executions to populate the Start menu. Value names are
     obfuscated with ROT-13 (e.g. 'PPyrnare.rkr' -> 'CCleaner.exe').
     Each value contains the program's run count, focus time, and last execution timestamp.
     Crucially, even if an attacker deletes prefetch files (*.pf), UserAssist often retains
     the execution record.
   - RunMRU:
     Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU
     Commands typed into the Windows 'Run' dialog (Win+R), such as 'sdelete', 'wevtutil',
     or 'cmd.exe', with the last write time of the key.
   - RecentDocs:
     Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs
     Recently accessed files and extensions, revealing files opened before wiping.

2. SOFTWARE hive (system-wide):
   - Installed Programs / Uninstall Keys:
     Keys: Microsoft\\Windows\\CurrentVersion\\Uninstall
           WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall
     Shows installed software, install dates, display version, and publisher (e.g. CCleaner,
     Eraser, BleachBit, File Shredder).

Honest limits:
- Portable tools (like standalone sdelete.exe or timestomp.exe run from a USB drive without
  installation) will not appear in the Uninstall registry keys.
- Command-line tools not launched via Explorer GUI may not leave UserAssist traces (prefetch
  or event logs are needed to catch them).
- Registry keys can also be manually deleted by an attacker; subkey last-write timestamps
  show when a key was modified.
"""
from __future__ import annotations

import codecs
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from Registry import Registry
import pandas as pd

from afd.parsers.filetime import filetime_to_datetime, filetime_to_iso


@dataclass
class UserAssistEntry:
    path: str
    raw_name: str
    run_count: int
    last_run: datetime | None
    last_run_raw: int
    user: str
    guid: str


@dataclass
class InstalledProgram:
    key_name: str
    display_name: str
    display_version: str
    publisher: str
    install_date: str
    install_location: str
    uninstall_string: str
    last_written: datetime | None


@dataclass
class RunMRUEntry:
    order: str
    command: str
    last_written: datetime | None
    user: str


def _rot13(s: str) -> str:
    """Decode ROT-13 encoded UserAssist entry names."""
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s


def _key_by_path(root, path: str):
    """Walk subkeys case-insensitively along a backslash-separated path."""
    curr = root
    parts = [p for p in path.split("\\") if p]
    for part in parts:
        found = None
        for sub in curr.subkeys():
            if sub.name().lower() == part.lower():
                found = sub
                break
        if found is None:
            return None
        curr = found
    return curr


def parse_userassist(hive: Registry.Registry, user: str = "") -> list[UserAssistEntry]:
    """Extract GUI program execution history from NTUSER.DAT UserAssist."""
    root = hive.root()
    ua_key = _key_by_path(root, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    if not ua_key:
        return []

    entries = []
    for guid_key in ua_key.subkeys():
        guid = guid_key.name()
        count_key = _key_by_path(guid_key, "Count")
        if not count_key:
            continue

        for val in count_key.values():
            raw_name = val.name()
            decoded = _rot13(raw_name)
            raw_data = val.value()

            if not isinstance(raw_data, (bytes, bytearray)):
                continue

            run_count = 0
            last_run_raw = 0

            # Win7 - Win11 format (72 bytes): run_count at offset 4, FILETIME at offset 60
            if len(raw_data) >= 68:
                run_count, = struct.unpack_from("<I", raw_data, 4)
                last_run_raw, = struct.unpack_from("<Q", raw_data, 60)
            # WinXP format (16 bytes): run_count at offset 4, FILETIME at offset 8
            elif len(raw_data) >= 16:
                run_count, = struct.unpack_from("<I", raw_data, 4)
                if run_count > 5:
                    run_count -= 5  # XP counter offset
                last_run_raw, = struct.unpack_from("<Q", raw_data, 8)

            last_run_dt = filetime_to_datetime(last_run_raw) if last_run_raw > 0 else None

            entries.append(UserAssistEntry(
                path=decoded,
                raw_name=raw_name,
                run_count=run_count,
                last_run=last_run_dt,
                last_run_raw=last_run_raw,
                user=user,
                guid=guid,
            ))
    return entries


def parse_installed_programs(hive: Registry.Registry) -> list[InstalledProgram]:
    """Extract installed software details from SOFTWARE hive (32-bit and 64-bit keys)."""
    root = hive.root()
    paths = [
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    programs = []
    seen_keys = set()

    for path in paths:
        uninstall_key = _key_by_path(root, path)
        if not uninstall_key:
            continue

        for app_key in uninstall_key.subkeys():
            kname = app_key.name()
            if kname in seen_keys:
                continue
            seen_keys.add(kname)

            def get_str(name: str) -> str:
                try:
                    v = app_key.value(name)
                    return str(v.value()).strip()
                except Registry.RegistryValueNotFoundException:
                    return ""
                except Exception:
                    return ""

            display_name = get_str("DisplayName")
            if not display_name:
                continue

            last_written = app_key.timestamp()
            if last_written and last_written.tzinfo is None:
                last_written = last_written.replace(tzinfo=timezone.utc)

            programs.append(InstalledProgram(
                key_name=kname,
                display_name=display_name,
                display_version=get_str("DisplayVersion"),
                publisher=get_str("Publisher"),
                install_date=get_str("InstallDate"),
                install_location=get_str("InstallLocation"),
                uninstall_string=get_str("UninstallString"),
                last_written=last_written,
            ))
    return programs


def parse_run_mru(hive: Registry.Registry, user: str = "") -> list[RunMRUEntry]:
    """Extract commands entered in the Win+R Run dialog from NTUSER.DAT."""
    root = hive.root()
    run_key = _key_by_path(root, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
    if not run_key:
        return []

    last_written = run_key.timestamp()
    if last_written and last_written.tzinfo is None:
        last_written = last_written.replace(tzinfo=timezone.utc)

    mru_order = ""
    try:
        mru_order = str(run_key.value("MRUList").value())
    except Exception:
        pass

    entries = []
    for val in run_key.values():
        name = val.name()
        if name.lower() == "mrulist":
            continue
        cmd = str(val.value()).strip()
        # Windows RunMRU commands end with '\1'
        if cmd.endswith(r"\1"):
            cmd = cmd[:-2]
        entries.append(RunMRUEntry(
            order=name,
            command=cmd,
            last_written=last_written,
            user=user,
        ))
    return entries


def load_hive(path: Path) -> Registry.Registry:
    """Open a registry hive file."""
    return Registry.Registry(str(path))


def load_registry_artifacts(registry_paths: list[Path]) -> dict[str, list]:
    """Parse all available registry hives.
    
    Identifies SOFTWARE and NTUSER.DAT hives automatically and returns:
    {
        'userassist': list[UserAssistEntry],
        'installed_programs': list[InstalledProgram],
        'run_mru': list[RunMRUEntry],
    }
    """
    res = {
        "userassist": [],
        "installed_programs": [],
        "run_mru": [],
    }

    for p in registry_paths:
        p = Path(p)
        try:
            hive = load_hive(p)
        except Exception:
            continue

        p_name = p.name.upper()
        # Per-user hive: NTUSER.DAT (could be in a user subfolder)
        if "NTUSER" in p_name:
            user = p.parent.name if p.parent.name.lower() != "registry" else "User"
            res["userassist"].extend(parse_userassist(hive, user=user))
            res["run_mru"].extend(parse_run_mru(hive, user=user))
        # System SOFTWARE hive
        elif "SOFTWARE" in p_name:
            res["installed_programs"].extend(parse_installed_programs(hive))

    return res
