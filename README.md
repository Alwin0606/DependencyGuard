
# DependencyGuard

A Python-based software dependency vulnerability scanner powered by the OSV vulnerability database.

## Features

- Scan pinned Python dependencies
- Identify known security advisories
- Deduplicate vulnerability records
- Generate JSON security reports
- Handle network errors
- Run automated unit tests

## Tech Stack

- Python 3.13
- Requests
- Packaging
- OSV API
- unittest

## Setup

Clone the repository, then run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the Scanner

```powershell
.\.venv\Scripts\python.exe main.py
```

The scan report is saved to `security-report.json`.

## Run Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_scanner.py
```

## Limitations

- Scans exact package versions specified with `==`.
- Uses the OSV vulnerability database.
- Requires an internet connection for live scans.
- Does not yet resolve transitive dependencies.
- Severity scores are not yet retrieved from official advisories.

## Future Improvements

- CVSS severity integration
- Dependency graph visualization
- GitHub Actions CI
- Transitive dependency analysis
- HTML security reports

## Disclaimer

This tool assists with dependency security analysis. Verify findings against official advisories before making remediation decisions.
