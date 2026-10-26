# Stage 8: Demo script (about 10 minutes)

Roles follow the code split:
- **Member 1**: parsers and file-system modules (MFT, timestomping, file wiping, free space, hidden files)
- **Member 2**: logs, registry and tool-trace modules (evtx, prefetch, UserAssist, correlation)
- **Member 3**: dashboard, timeline and report

The bullet points are cues, not lines to read out. Say them in your own words.

## Before the demo (day before)
1. Run both cases on the laptop you will present from, so nothing heavy runs live:
   ```powershell
   python run_detectors.py C:\forensics\evidence\images\tampered.E01 tampered --reference-time <time> --ml --report
   python run_detectors.py C:\forensics\evidence\images\clean.E01 clean --reference-time <time> --ml --report
   ```
2. For the live run, keep a **small artifact folder** ready, e.g. `C:\forensics\evidence\artifacts\tampered`. Analysing a folder takes seconds; a full image takes minutes.
3. Open `tampered\report.pdf` in a viewer, and have FTK Imager's `tampered.E01.txt` and Autopsy's screenshots ready.
4. Turn off notifications. Set the browser zoom to 110–125% so the room can read it.
5. Fallback if anything breaks: *Open saved case → tampered* shows the same results instantly.

## Flow

| Time | Who | Show | Cue |
|---|---|---|---|
| 0:00 | M3 | Title slide / dashboard home | Problem: attackers fake dates, clear logs, wipe files. Manual checks are slow; the tool automates them and reports *likely*, not proof. |
| 1:00 | M1 | VM ground-truth table (TEST_PLAN §2) | What we did in our own VM and when. This is what the tool should find. |
| 2:00 | M3 | Sidebar → artifact folder → **Run analysis** | Every file is hashed on load; progress shows the six modules. |
| 3:00 | M3 | **Overview** tab | Counts per confidence level; which modules ran or were skipped, and why; campaign alert. |
| 3:30 | M1 | **Findings** → filter *timestomp* → open the HIGH one | `$SI` created 2019 vs `$FN` created on the test day; whole-second dates; "MFT changed" shows when the dates were edited. Point to *Innocent explanations considered*. |
| 4:30 | M1 | Findings → *file_wiping* / *hidden_files* | `ZZZZZZZZ.ZZZ` = SDelete's 26 renames. ADS with an `MZ` header = executable hidden behind a text file. |
| 5:30 | M2 | Findings → *log_wiping* / *tool_traces* | Event 1102 / 104; `WEVTUTIL.EXE`, `SDELETE64.EXE` in prefetch; RunMRU command. Built-in tools are scored lower. |
| 6:30 | M2 | One finding with a *Corroborated:* reason | Only an execution trace raises confidence; a tool on disk is context only. |
| 7:00 | M3 | **Timeline** tab | The cover-up in order. Compare with the notebook times. Explain *Time meaning*. |
| 8:00 | M3 | **Evidence & custody** → *Re-verify* (and media hash vs FTK `.txt`) | Evidence unchanged; append-only custody log of every action. |
| 8:30 | M3 | **Report & export** → Generate → open PDF | Hashes, method, findings, timeline, limits. The conclusion box is filled by the examiner, not the tool. |
| 9:00 | M1 | *Open saved case → clean* | False-positive check: no HIGH; each MEDIUM explained (installer, extraction, update). |
| 9:30 | M2 | Autopsy comparison table | What both tools found; what only one found, and why. |
| 10:00 | All | Limits slide | Skilled attacker can remove tool traces; `$FN` can be changed by moving files; Windows/NTFS only. |

## If asked to show something live
- *"Change a threshold"*: open `config/settings.yaml`, e.g. `timestomp.medium_at`, re-run on the artifact folder, and show the count change.
- *"Show the raw evidence"*: *Findings → Raw evidence* holds the exact `$SI` / `$FN` values, record IDs and prefetch file names.
- *"Prove the evidence did not change"*: *Re-verify evidence hashes* re-hashes every file and logs the check.
- *"Run the tests"*: `python -m pytest -q`. The tests build synthetic `$MFT` records and run the real parsers on them.
