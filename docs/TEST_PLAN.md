# Stage 7: Test plan, test cases and false-positive reduction

Everything here runs **inside your own test VM**. Never run these commands on a real or shared machine.

The plan produces **two disk images of the same VM**:

| Image | Contains | Purpose |
|---|---|---|
| `clean` | Normal use only | False-positive check (step 5) |
| `tampered` | The same VM, later, after the anti-forensic actions | Detection check (step 4) |

Because both come from one VM, the only difference is what you did in step 2. That is your ground truth.

Keep the **lab notebook on the host** (a spreadsheet is fine), never inside the VM. Writing notes in the VM would add your own activity to the evidence.

---

## 0. Host preparation (once)

- Hypervisor: VirtualBox, VMware Workstation or Hyper-V.
- Windows 10 or 11 ISO. Microsoft's free evaluation ISO is fine.
- On the host: FTK Imager 4.x, Autopsy 4.x, this project with its venv (see README), and optionally Eric Zimmerman's MFTECmd and PECmd.
- Folders: `C:\forensics\evidence\images`, `C:\forensics\evidence\artifacts`, `C:\forensics\cases`.

## 1. Build the VM with normal activity

### 1.1 Create the VM
- 2 vCPU, 4 GB RAM, a **40 GB** disk. A small disk keeps the free-space wipes and imaging short.
- Install Windows with a local account, e.g. `labuser`. Let Windows Update finish and reboot.

### 1.2 Baseline settings (elevated PowerShell in the VM)
```powershell
# 1. BitLocker / device encryption must be OFF, or the image cannot be read
manage-bde -status C:
manage-bde -off C:                     # only if it says "Protection On" / "Encrypted"

# 2. Prefetch must be enabled (value 3)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher
reg add  "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f

# 3. Hibernation / Fast Startup off, so shutdown leaves NTFS cleanly closed
powercfg /h off

# 4. Optional but useful: log process creation (Event 4688) with command lines
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# 5. Note the VM's time zone (all tool output is UTC)
Get-TimeZone
```

### 1.3 Normal activity (spread over at least a few hours, ideally 1–2 days)
Real logs need history. A VM used for 10 minutes looks unusual to the log and ML modules.

1. Create and edit documents in `Documents` (Notepad, WordPad). Save several versions.
2. Browse with Edge. Download a few files, including a ZIP.
3. Install 7-Zip and Notepad++. **Installers are a known false-positive source**, which is why they are here.
4. Extract the ZIP with 7-Zip into `Documents\Extracted`. Extraction keeps original dates, another known false-positive source.
5. Copy a folder of files into the VM (shared folder or USB pass-through).
6. Reboot two or three times. Leave the VM off overnight once: this creates a log gap that **is** explained by a shutdown.
7. Run a Windows Update check.

Write the date and time of each block in the notebook.

### 1.4 Capture the clean image
Shut the VM down (Start → Shut down, not suspend), then follow **section 3**, naming the image `clean`.

---

## 2. Anti-forensic actions (tampered image)

Boot the VM again and wait 5 minutes for startup activity to settle. Open **PowerShell as Administrator**.

Before each action, write the host clock time (UTC) in the notebook. Leave **at least 2 minutes** between actions so the timeline shows them as separate steps.

### 2.0 Set up test files
```powershell
New-Item -ItemType Directory C:\Lab\Secret -Force | Out-Null
1..6 | ForEach-Object { Set-Content "C:\Lab\Secret\doc$_.txt" ("confidential record $_ " * 300) }
Set-Content C:\Lab\Secret\small.txt ("x" * 300)          # small enough to be resident in the MFT
Copy-Item C:\Windows\System32\notepad.exe C:\Windows\Temp\updater.exe
```
**Wait at least 2 minutes** before 2.1. The detector notices dates edited after the file arrived (60 s tolerance).

### 2.1 Timestomping (Module 1)
PowerShell's date setters call `SetFileTime`, which changes `$STANDARD_INFORMATION` only. `$FILE_NAME` keeps the real arrival time.
```powershell
$old = Get-Date "2019-03-04 10:00:00"                     # whole seconds, like most tools
foreach ($p in "C:\Lab\Secret\doc1.txt", "C:\Windows\Temp\updater.exe") {
    $f = Get-Item $p
    $f.CreationTime = $old; $f.LastWriteTime = $old; $f.LastAccessTime = $old
}
# An impossible future date
(Get-Item C:\Lab\Secret\doc3.txt).LastWriteTime = Get-Date "2031-01-01 00:00:00"

Get-Item C:\Lab\Secret\doc1.txt | Format-List CreationTime, LastWriteTime   # shows 2019
```
Optional, for Module 6: download **NewFileTime** (SoftwareOK, freeware) and use it to change `doc2.txt` to an old date. This leaves a `NEWFILETIME*.EXE` prefetch file.

Expected: `doc1.txt` and `updater.exe` flagged. `updater.exe` should be HIGH (whole seconds, edited after arrival, Temp folder). `doc3.txt` flagged for a future date.

### 2.2 Hidden and disguised files (Module 5)
```powershell
Set-Content C:\Lab\Secret\notes.txt "meeting notes"
# Executable hidden in an Alternate Data Stream (cmd's type writes binary data correctly)
cmd /c "type C:\Windows\System32\notepad.exe > C:\Lab\Secret\notes.txt:payload.exe"
# Script hidden in an ADS
Set-Content -Path C:\Lab\Secret\notes.txt -Stream run.ps1 -Value 'Write-Host "hidden"'
# Executable disguised as a picture
Copy-Item C:\Windows\System32\notepad.exe C:\Lab\Secret\holiday.jpg
# Check: list the streams
Get-Item C:\Lab\Secret\notes.txt -Stream *
```
Expected: the ADS findings. `holiday.jpg` is only checked when you analyse the **disk image**, because the tool must read the file's first bytes from disk. From exported artifacts alone, only files under about 700 bytes are checked (see Limits).

### 2.3 Secure deletion (Module 3)
Download SDelete from Microsoft Sysinternals into `C:\Lab\Tools`.
```powershell
cd C:\Lab\Tools
.\sdelete64.exe -accepteula -p 1 C:\Lab\Secret\doc4.txt C:\Lab\Secret\doc5.txt C:\Lab\Secret\small.txt
```
SDelete overwrites each file, renames it 26 times (`AAAA.AAA` … `ZZZZ.ZZZ`), then deletes it.

Expected: deleted MFT entries named like `ZZZZZZZZ.ZZZ` (HIGH), and `SDELETE64.EXE` in prefetch (Module 6).

Optional: install **Eraser**, right-click `doc6.txt` → Eraser → Erase.

### 2.4 CCleaner (Module 6, and logs if selected)
Install CCleaner Free. Open *Custom Clean*, keep the defaults, and press *Run Cleaner*. If your version shows *Windows Event Logs* under *Windows → Advanced*, tick it to test correlation with Module 2.

Expected: CCleaner in prefetch, UserAssist and the Uninstall key.

### 2.5 Free-space wiping (Module 4)
This takes time: 3 passes over all free space, roughly 20–60 minutes on a 40 GB disk.
```powershell
cipher /w:C:\Lab
```
A quicker zero-only alternative is `C:\Lab\Tools\sdelete64.exe -z C:`. Zero-fill is reported as LOW only, because never-written space also reads as zeros.

Expected: a random-pass finding (MEDIUM) if most sampled free chunks are random, and `CIPHER.EXE` in prefetch (MEDIUM, built-in tool).

### 2.6 Clearing the event logs (Module 2), done last, as an attacker would
For a RunMRU trace, press **Win+R**, type the command, and press **Ctrl+Shift+Enter** to run it as administrator:
```
wevtutil cl Security
```
Then in the admin PowerShell:
```powershell
wevtutil cl System
Clear-EventLog -LogName Application      # Windows PowerShell 5.1
```
Expected: Event **1102** at the start of the new Security log, Event **104** in System, `WEVTUTIL.EXE` in prefetch, and RunMRU entries.

Optional (time gap): disable auditing with `auditpol /set /category:* /success:disable /failure:disable`, use the VM normally for more than 6 hours, then re-enable it with `/success:enable`. Windows logs Event 4719 for the policy change.

### 2.7 Shut down and capture
Wait 1 minute (prefetch files are written about 10 s after a program starts), shut the VM down, and follow section 3, naming the image `tampered`.

### Ground-truth table (fill in on the host)

| # | Action | Time (UTC) | Expected module | Expected finding |
|---|---|---|---|---|
| 1 | Timestomp doc1.txt, updater.exe | | 1 | si_before_fn (+ whole seconds, edited after arrival) |
| 2 | Future date doc3.txt | | 1 | future |
| 3 | ADS payload.exe, run.ps1 | | 5 | ADS executable / script |
| 4 | holiday.jpg (renamed exe) | | 5 | header mismatch (image input) |
| 5 | SDelete doc4, doc5, small | | 3 + 6 | mangled names; SDELETE prefetch |
| 6 | CCleaner run | | 6 | prefetch, UserAssist, Uninstall |
| 7 | cipher /w | | 4 + 6 | random free space; CIPHER prefetch |
| 8 | wevtutil cl Security / System | | 2 + 6 | 1102, 104; WEVTUTIL prefetch, RunMRU |

---

## 3. Capturing the image with FTK Imager

Image a **powered-off** VM. Imaging a running system changes the evidence while you copy it.

### 3.1 Turn the virtual disk into a raw disk (on the host)
```powershell
# VirtualBox
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" clonemedium disk "C:\VMs\Win10\Win10.vdi" C:\forensics\evidence\images\tampered.img --format RAW
# Hyper-V (the tool reads fixed VHDs directly)
Convert-VHD -Path C:\VMs\Win10.vhdx -DestinationPath C:\forensics\evidence\images\tampered.vhd -VHDType Fixed
# VMware Workstation: creates tampered-flat.vmdk, which is a raw disk; rename it to tampered.img
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" -r C:\VMs\Win10\Win10.vmdk -t 2 C:\forensics\evidence\images\tampered.vmdk
```
Record its hash: `Get-FileHash C:\forensics\evidence\images\tampered.img -Algorithm SHA256`

### 3.2 Create the E01
1. FTK Imager → *File → Create Disk Image* → *Image File* → select `tampered.img` (or the `.vhd`).
2. *Add…* → **E01** → fill in Case Number, Evidence Number, Description, Examiner.
3. Destination `C:\forensics\evidence\images`, file name `tampered`, Image Fragment Size `0` (one file), Compression `6`.
4. Tick **Verify images after they are created** → *Start*.
5. FTK writes `tampered.E01` and `tampered.E01.txt`. The `.txt` holds the MD5 and SHA1 of the **disk data** and the verification result. Keep it.

### 3.3 Integrity check
In the dashboard (*Evidence & custody → Compute media hash*), or from the command line:
```powershell
python -c "from afd.parsers.image_reader import media_hash; print(media_hash(r'C:\forensics\evidence\images\tampered.E01'))"
```
- The **MD5** must equal the MD5 in `tampered.E01.txt`.
- The **SHA-256** must equal `Get-FileHash` of `tampered.img` from 3.1. Same disk data, different container.

### 3.4 Optional: export artifacts with FTK Imager
*File → Add Evidence Item → Image File* → `tampered.E01`, then right-click → *Export Files* for:
`[root]\$MFT`, `Windows\System32\winevt\Logs\*.evtx`, `Windows\System32\config\SOFTWARE` and `SYSTEM`, `Users\<user>\NTUSER.DAT`, `Windows\Prefetch\*.pf`. Put them in `C:\forensics\evidence\artifacts\tampered\`. The tool also extracts these itself when given the E01.

---

## 4. Run the tool and check detection

```powershell
# Use the time you shut the VM down as the reference time
python run_detectors.py C:\forensics\evidence\images\tampered.E01 tampered --reference-time 2026-11-02T14:30:00Z --ml --timeline --report
streamlit run app.py          # then "Open saved case" -> tampered
```
For each row of the ground-truth table, record:

| # | Detected? | Finding ID | Confidence | Tool time (UTC) | Notebook time | Difference | Notes |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |

Also check:
- The timeline puts the episodes in the same order as your notebook.
- Each "Time meaning" makes sense. Prefetch gives the last run; timestomped files give `$SI` "MFT changed", i.e. when the dates were edited.
- The custody log lists every evidence file with hashes, and *Re-verify* still matches.

A miss is a result, not a failure. Write down why. Common causes: the action's trace was itself wiped (CCleaner can clear prefetch), the action was outside the analysed artifacts, or a threshold was not reached.

## 5. Clean image: false-positive check

```powershell
python run_detectors.py C:\forensics\evidence\images\clean.E01 clean --reference-time <clean shutdown time> --ml --report
```
Target: **no HIGH findings**. For every MEDIUM, look at its reasons and decide:
- **Explained**: an installer, an extracted archive, Windows Update, your overnight shutdown. Record the explanation.
- **Unexplained**: investigate before tuning anything.

Count false positives per module, before and after any tuning.

## 6. Comparison with Autopsy

1. Autopsy → *New Case* → *Add Data Source* → *Disk Image* → `tampered.E01`.
2. Ingest modules: *Recent Activity*, *File Type Identification*, *Extension Mismatch Detector*, *Data Source Integrity*, *Interesting Files Identifier*, *Embedded File Extractor*.
3. Compare:

| What | Where in Autopsy | Compare with |
|---|---|---|
| Image hash | Data Source Integrity result | Our media hash / FTK `.txt` |
| `$SI` vs `$FN` dates | Select the file → *File Metadata* tab (istat output lists both attributes) | Module 1 evidence |
| Deleted `ZZZZ…` entries | *Views → Deleted Files* | Module 3 |
| ADS | Shown as `notes.txt:payload.exe` in the folder view | Module 5 |
| Renamed exe | *Extension Mismatch Detected* | Module 5 |
| Programs run | *Data Artifacts → Run Programs* (prefetch), *Programs Run / UserAssist* | Module 6 |
| Installed programs | *Installed Programs* | Module 6 |
| Sequence | *Timeline* viewer | Our timeline |

Autopsy has no event-log clearing check. For Module 2, cross-check with Event Viewer on the host (*Open Saved Log* → filter Event IDs 1102 and 104) or:
```powershell
Get-WinEvent -Path .\Security.evtx -FilterXPath "*[System[EventID=1102]]" | Format-List TimeCreated, Message
```
Optional parser checks: `MFTECmd.exe -f $MFT --csv out` gives `SI<FN` and `uSecZeros` columns to compare with Module 1, and `PECmd.exe -d Prefetch --csv out` gives run times to compare with Module 6.

Record, per action: found by our tool / found by Autopsy / found by both / found by neither.

---

## 7. How false positives are reduced (and the knobs)

All weights and thresholds are in `config/settings.yaml`. **Tune on the clean image, then re-check the tampered image.** Tuning only until the tampered image looks good just fits the tool to your own test.

| Source of false positives | What the tool does | Setting |
|---|---|---|
| Installers and archive extraction (whole-second original dates, many files at once) | Bulk pattern lowers the score to LOW | `timestomp.bulk_*`, `benign_path_prefixes` |
| Windows setup and updates | Volume-wide burst lowers the score to LOW | `timestomp.volume_burst_*` |
| Folders (their "MFT changed" moves on every new file) | Skipped | `timestomp.include_directories` |
| Log gaps from shutdowns, sleep, clock changes | Not reported when a System-log anchor is near | `log_wiping.anchor_window_minutes` (supply `System.evtx`) |
| `cipher.exe` and `wevtutil.exe` exist in System32 on every Windows, and Windows runs `wevtutil` itself during setup | Not reported from the MFT; executions score 4 lower (LOW), raised to MEDIUM when a matching log clear or wipe is found nearby | `tool_traces.builtin_*`, `builtin: true` |
| A tool on disk is not a tool that ran | Presence never raises another finding's confidence; only prefetch, UserAssist and RunMRU do | scoring.py |
| Several LOW findings close together; ML outliers | LOW and ML findings never form a "campaign" | `analysis.campaign_min_confidence` |
| Never-written free space is zeros; deleted ZIP/CAB data looks random | Only unallocated clusters (from `$Bitmap`) are sampled; zero-fill is LOW; random must cover ≥60% | `freespace.*` |
| Small deleted Windows servicing files that are all zeros | A zero fill alone is LOW; 0xFF or a repeated byte stays MEDIUM | `file_wiping.weights` |
| Hash-named files (`<sha256>.cat`, `Wrapper-<hash>~...~amd64~~10.0.cat`) | Not treated as random wiper names | file_wiping.py |
| NTFS's own streams (`$UsnJrnl:$J`, `$Repair:$Corrupt`) | Files under `\$Extend` are skipped | `hidden_files.ntfs_metadata_prefixes` |
| Isolation Forest outliers | Always LOW: supporting evidence only | ml_anomaly.py |

Result on the clean Windows 11 test image (`clean_baseline.vhd`): **0 HIGH, 0 MEDIUM**. Before these
rules the same image gave 13 HIGH / 3,700 MEDIUM (timestomping alone) and then 3 HIGH / 2,256 MEDIUM
(other modules, including 2 false "campaigns"). Each case has a test in
`tests/test_false_positive_fixes.py`.

Record each change you make: setting, old value, new value, false positives before and after.

## Limits to state honestly
- Findings say *likely*, never proof. Every finding lists the innocent explanations considered.
- A careful attacker can also remove the cleaner's own traces: prefetch, UserAssist, its files.
- Timestomping that also changes `$FN` (move the file to another folder and back), or moves dates forward, is not detected. `$UsnJrnl` and `$LogFile` analysis would help (future work).
- Header-mismatch on large files needs the full disk image. With exported artifacts only, resident files (under ~700 bytes) are checked.
- Log editing that keeps record IDs contiguous is not detected.
- SSD TRIM and thin-provisioned VM disks return zeros for deleted data, so zero-fill is weak evidence.
- Windows and NTFS only. Linux (ext4, journald) is future work.
