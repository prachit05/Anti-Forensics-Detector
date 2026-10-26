# Anti-Forensics Detector

Analyses a Windows (NTFS) disk image or extracted artifacts for signs of evidence
tampering: timestomping, log clearing, file/free-space wiping, hidden files and
anti-forensic tool use. Findings are rated by confidence and placed on one timeline.

Findings mean "likely", not proof. Scope is Windows and NTFS only.

## Project layout

```
CF/
â”œâ”€â”€ app.py                  Streamlit dashboard (Stage 6)
â”œâ”€â”€ check_env.py            Checks that all libraries import
â”œâ”€â”€ requirements.txt
â”œâ”€â”€ config/settings.yaml    Detection thresholds (Stage 3+)
â”œâ”€â”€ afd/
â”‚   â”œâ”€â”€ core/               Evidence loading, hashing, chain-of-custody log, Finding model
â”‚   â”œâ”€â”€ parsers/            image_reader, mft, evtx, registry, prefetch     (Stage 2)
â”‚   â”œâ”€â”€ detectors/          timestomp, log_wiping                            (Stage 3)
â”‚   â”‚                       file_wiping, freespace, hidden_files, tool_traces (Stage 4)
â”‚   â”œâ”€â”€ analysis/           scoring, timeline, ml_anomaly                    (Stage 5)
â”‚   â”œâ”€â”€ reporting/          HTML/PDF report, CSV/JSON export, templates/     (Stage 6)
â”‚   â””â”€â”€ pipeline.py         One analysis run, shared by the CLI and the dashboard
â”œâ”€â”€ tests/                  pytest tests and sample_data/
â”œâ”€â”€ run_detectors.py        Command-line run (same pipeline as the dashboard)
â””â”€â”€ docs/                   TEST_PLAN.md (Stage 7), DEMO_SCRIPT.md and VIVA_QA.md (Stage 8)
```

## Setup (Windows 10/11, Python 3.12 64-bit)

1. **Use Python 3.12.** pytsk3 and libewf-python ship Windows wheels for 3.12;
   3.13/3.14 may try to compile from source and fail. Check: `py -0p`.

2. **Create the virtual environment outside OneDrive.** OneDrive would try to sync
   thousands of venv files, and long paths can exceed Windows' 260-character limit:
   ```powershell
   py -3.12 -m venv $env:USERPROFILE\venvs\afd
   & $env:USERPROFILE\venvs\afd\Scripts\Activate.ps1
   ```
   If PowerShell blocks the script:
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

3. **Install the dependencies:**
   ```powershell
   cd $env:USERPROFILE\OneDrive\Desktop\CF
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Verify:**
   ```powershell
   python check_env.py
   ```
   Every required line should say `[OK]`.

5. **External tools for cross-checking** (install on the host, not in the venv):
   - FTK Imager: capture the image and export artifacts ($MFT, .evtx, hives, prefetch).
   - Autopsy 4.x: compare its results with this tool.
   - Optional: Eric Zimmerman's MFTECmd and PECmd, to validate our MFT and prefetch parsers.

## Evidence and case folders

Evidence and output live **outside OneDrive**, so multi-GB images are never uploaded.

| Setting | Default | Override |
|---|---|---|
| Evidence (input, read-only) | `C:\forensics\evidence` | `AFD_EVIDENCE_DIR` |
| Cases (output) | `C:\forensics\cases` | `AFD_CASES_DIR` |

Defaults are set in `config/settings.yaml`. An environment variable overrides the file:
```powershell
$env:AFD_EVIDENCE_DIR = "D:\evidence"
```
Suggested layout inside the evidence folder:
```
C:\forensics\evidence\
â”œâ”€â”€ images\       win10_test.E01 (or .dd/.raw) plus FTK Imager's .txt hash log
â””â”€â”€ artifacts\    $MFT, *.evtx, NTUSER.DAT, SOFTWARE, SYSTEM, *.pf
```

- Two inputs are supported: **exported artifacts** (the primary input: small and fast) and
  **full disk images** (E01 or raw).
- Work on a **copy**. Keep the original and its FTK Imager hash file separately.
- The tool hashes evidence on load (MD5 and SHA-256) and logs every action to
  `<cases_dir>\<case>\custody_log.jsonl`.

## Stage 3: detectors (timestomping and log wiping)

Run on an image or a folder of exported artifacts:

```powershell
python run_detectors.py C:\forensics\cases\stage2_test_clean_v2\extracted clean_check
python run_detectors.py <image or folder> my_case --min-confidence LOW --limit 0
python run_detectors.py <image or folder> my_case --reference-time 2026-10-25T09:30:00Z
```

It prints a count per confidence level and up to 50 MEDIUM/HIGH findings (change with
`--min-confidence` and `--limit`), writes *every* finding to `<cases_dir>\<case>\findings.json`
and logs each step to the custody log. Run the tests with `python -m pytest`.

| Detector | File | Looks for |
|---|---|---|
| Timestomping (T1070.006) | `afd/detectors/timestomp.py` | `$SI` created earlier than `$FN` created, whole-second `$SI` dates, edit trace in `$SI` "MFT changed", dates copied from a system file, future or zeroed dates |
| Log wiping (T1070.001) | `afd/detectors/log_wiping.py` | Events 1102 / 104, missing record IDs, unexplained silence, header expecting more records, log history missing |

**Confidence** means how sure we are the *action* happened, not who did it or why.
Each finding lists its reasons and the innocent explanations that were considered.
Scores and thresholds are in `config/settings.yaml` under `detection:`.

**False positives that are handled on purpose**
- Installers and archive extraction (many files, whole-second original dates, same folder,
  arriving within seconds, often under Program Files) are downgraded to LOW with a note.
- Windows setup and updates (thousands of files across many folders arriving within minutes,
  with no "edited after arrival" trace) are downgraded the same way.
- Folders are skipped: their "MFT changed" time moves whenever a file is added to them.
- Gaps in a log are not reported when a restart, sleep or clock-change event from the System
  log sits next to them. Supply `System.evtx` along with the log you care about.
- A header that is *behind* the records (dirty file) is not a finding; one that is *ahead* is.

**Known limits:** a careful attacker can also edit `$FN` (for example by moving the file) or
stomp forward; a copy that keeps every date looks like `si_before_fn` and stays LOW unless
other indicators join it; log editing that leaves record IDs contiguous is not detectable here.

## Stages 4 and 5: other detectors, correlation, timeline and ML

`run_detectors.py` runs all six detectors, then correlation and the timeline. Free-space
analysis needs a disk image; the other modules also work on an artifact folder. Add `--ml`
for the Isolation Forest check and `--timeline` to print the timeline narrative.

| Module | File | Looks for |
|---|---|---|
| File wiping (T1070.004) | `afd/detectors/file_wiping.py` | SDelete-style names (`ZZZZZZZZ.ZZZ`), random wiper names, deleted resident content overwritten with 0x00 / 0xFF / a repeated byte |
| Free-space wiping (T1070.004) | `afd/detectors/freespace.py` | Zero, 0xFF, repeated-byte or random fill across **unallocated clusters only** (read from `$Bitmap`) |
| Hidden files (T1564.004, T1036.008) | `afd/detectors/hidden_files.py` | Script or oversized Alternate Data Streams, executables or archives with a disguising extension |
| Tool traces (T1070) | `afd/detectors/tool_traces.py` | CCleaner, SDelete, Eraser, BleachBit, timestamp editors, `wevtutil`, `cipher` in prefetch, UserAssist, Uninstall keys, RunMRU and the MFT |
| Correlation | `afd/analysis/scoring.py` | A tool run next to its matching action raises both; 3+ techniques at MEDIUM/HIGH within 2 hours form a campaign |
| Timeline | `afd/analysis/timeline.py` | All dated findings in order, grouped into episodes (30-minute gaps) |
| ML (optional) | `afd/analysis/ml_anomaly.py` | Isolation Forest outliers in log intervals and `$SI`/`$FN` differences |

**False positives found on the clean Windows 11 image, and how they are handled**

On a clean, freshly installed and updated VM the first version raised 3 HIGH and 2,256
MEDIUM findings. All of these are now LOW or not reported:

| What a clean system did | Was | Now |
|---|---|---|
| Windows setup and an update produced 100,000+ LOW findings in two one-hour windows, which the correlation turned into 2 "campaigns" | HIGH | Only MEDIUM/HIGH findings from rule-based detectors count towards a campaign; ML never does |
| Windows ran `wevtutil` 4 times during setup (registering event logs) | HIGH | Built-in tools (`wevtutil`, `cipher`) are LOW when run alone, and become MEDIUM only when the matching action (a log clear, a wipe) is found nearby. Windows' own copies under `\Windows\` are not reported |
| 2,028 small deleted servicing files (`.manifest`, `.cat`) were all zeros, 341 of them completely | MEDIUM | A zero fill alone is LOW; 0xFF or another repeated byte is still MEDIUM; a pattern seen only in the first 64 bytes counts less |
| 361 deleted catalog files named after their hash (`<sha256>.cat`, `Wrapper-<sha256>~31bf...~amd64~~10.0.26100.9444.cat`) looked like random wiper names | MEDIUM | A wiper's random name is a plain run of letters and digits; hash names and names with separators are not counted |
| About half of the unallocated space was zeros (never-written VM disk) | MEDIUM | Zero fill alone is LOW; it is raised when a free-space wiper is also found to have run |
| NTFS's own streams (`$UsnJrnl:$J`, `$Repair:$Corrupt`, `$Tops:$T`) | MEDIUM | Files under `\$Extend` are NTFS metadata and are skipped |
| Isolation Forest outliers (Windows servicing files, setup-time log intervals) | MEDIUM | ML findings are always LOW supporting evidence |

The timeline and the on-screen list show MEDIUM and above by default (`--min-confidence`);
`findings.json` always keeps every finding. Each case is covered by a regression test in
`tests/test_false_positive_fixes.py`, together with a control showing that real tampering is
still caught.
## Stage 6: dashboard and report

```powershell
streamlit run app.py
```

- **Sidebar:** run a new analysis on an image or artifact folder, or reopen a saved case (no re-parsing).
- **Overview:** counts per confidence level, which modules ran or were skipped and why, campaign alerts, episodes.
- **Findings:** filter by confidence, module or text; each finding shows its reasons, the innocent explanations considered, and the raw evidence.
- **Timeline:** chart and episode tables. *Time meaning* says what each time stands for.
- **Evidence & custody:** hashes, *Re-verify evidence hashes*, *Compute media hash* (to compare with FTK Imager's `.txt`), and the custody log.
- **Report & export:** writes `report.html`, `report.pdf`, `findings.csv` and `analysis.json` to the case folder. Each output is hashed into the custody log.

The report's **conclusion** comes from the examiner's own text box. The tool never writes it; if the box is empty, the report shows a placeholder. Everything else in the report (hashes, method, findings, timeline, limits, custody log) is filled from the analysis.

Command-line equivalent: `python run_detectors.py <image or folder> <case> --report`.

Every run saves `findings.json`, `timeline.json` and `case_summary.json` in the case folder.

## Stage 7: testing and false positives

See [docs/TEST_PLAN.md](docs/TEST_PLAN.md). It covers:
- building the VM
- every anti-forensic action, with exact commands
- FTK Imager capture and hash checks
- running the tool
- the clean-image false-positive check
- the Autopsy comparison
- the settings that control false positives

Unit tests: `python -m pytest -q`. The dashboard test uses Streamlit's own test runner, so no browser is needed.

## Stage 8: demo and viva

- [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md): 10-minute demo with roles and a fallback.
- [docs/VIVA_QA.md](docs/VIVA_QA.md): likely questions with short answers.

