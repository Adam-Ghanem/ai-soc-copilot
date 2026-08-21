# Contributing to AI SOC Copilot

Thanks for helping improve AI SOC Copilot.

## Development setup

AI SOC Copilot requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -e '.[dev]'
```

## Run the tests

From the repository root, run:

```bash
python -m pytest -q
```

The repository configures `src/` on the pytest import path, so you do not need to set `PYTHONPATH` manually. If `pytest` is not installed, install the development extras first with `pip install -e '.[dev]'`.

Before opening a pull request, make sure the test suite passes locally.

## Run the sample workflow

To exercise the complete local-first pipeline with the included synthetic events:

```bash
python -m ai_soc_copilot.cli \
  --input samples/security_events.jsonl \
  --output reports/incident_report.md \
  --case-json reports/cases.json
```

This should process the sample events and write both a Markdown incident report and structured case JSON under `reports/`.

## Making changes

- Keep changes focused and explain the user or analyst value.
- Preserve deterministic behavior for parsing, detection, triage, and case generation.
- Do not add real credentials, private incident data, or external network dependencies to samples or tests.
- Add or update tests when behavior changes.
- Keep defensive and safe-by-default behavior intact.

## Pull requests

Please include:

1. A short summary of the problem and solution.
2. Tests run locally.
3. Any security or compatibility considerations.

Small documentation and test improvements are welcome.
