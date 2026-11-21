# File Triage & Hash Analysis

COMP H2702 – Scripting for Cybersecurity, Scenario C.

This program inventories safe local files, calculates SHA-256 hashes, compares them with a supplied reference CSV, identifies files with matching content, and saves a JSON triage report. It does not execute samples or upload files.

## Requirements

Python 3.9 or later. No third-party packages are needed.

## Run

Open a terminal in the project folder and run:

```bash
python file_triage.py
```

The default input is `samples/`, the default reference is `samples/hashes_reference.csv`, and the output is `output/triage_report.json`.

To analyse another safe folder:

```bash
python file_triage.py "path/to/safe/folder" --references "samples/hashes_reference.csv"
```

## Input files

The supplied `samples/` folder contains five synthetic teaching samples, a reference CSV and its original README. The program skips the reference CSV itself. It does not modify input files.

## Interpretation and limitations

KNOWN means the file's hash is in the supplied reference list. UNKNOWN means it is not in that list. Neither status proves a file is safe or malicious. Identical hashes identify identical file content, not behaviour. A modified file can have a different hash.

## Error handling

Missing input folders, malformed reference CSV rows, inaccessible files and report-write failures produce explanatory errors. File-specific read failures are included in the report when possible.
