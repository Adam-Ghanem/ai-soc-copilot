# AI SOC Copilot

> **Turn noisy security alerts into clear, evidence-driven SOC decisions.**

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Adam-Ghanem/ai-soc-copilot/ci.yml?label=CI" alt="CI">
  <img src="https://img.shields.io/github/stars/Adam-Ghanem/ai-soc-copilot" alt="GitHub stars">
  <img src="https://img.shields.io/github/commit-activity/m/Adam-Ghanem/ai-soc-copilot" alt="Commit activity">
  <img src="https://img.shields.io/github/languages/top/Adam-Ghanem/ai-soc-copilot" alt="Top language">
</p>

AI SOC Copilot is a **local-first defensive SOC assistant** that transforms SIEM/EDR-style alerts into structured findings, prioritized cases, analyst guidance, and incident-ready reports.

It focuses on **transparent detection, deterministic triage, evidence preservation, and safe workflows** rather than black-box security claims.

## ⚡ Highlights

- 📥 Strict JSONL alert ingestion and schema validation
- 🔎 Rule-based detection engine
- 📊 Transparent risk scoring and prioritization
- 🧩 Deterministic correlation and case grouping
- 🕵️ Safe local indicator enrichment
- 🗂️ Analyst-ready case queue with timelines and observables
- 📝 Markdown incident report generation
- 📦 Structured JSON case output for dashboards and automation
- 🧪 Synthetic security events and automated validation tests
- 🛡️ Secure, local-first defaults with no arbitrary execution

## 🏗️ Architecture

```text
                  ┌──────────────────────┐
                  │   SIEM / EDR Alerts  │
                  │      JSONL Input     │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │ Parser + Validation  │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │ Detection Rule Engine│
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │    Risk / Triage     │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │  Local Enrichment    │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │     Case Builder     │
                  └──────────┬───────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
             ┌──────▼──────┐   ┌──────▼──────┐
             │   Markdown  │   │    JSON     │
             │ Incident    │   │    Cases    │
             │   Report    │   │   Output    │
             └─────────────┘   └─────────────┘
```

The pipeline keeps **ingestion, detection, scoring, enrichment, correlation, and reporting** separated so each stage remains testable and explainable.

## 🧠 How It Works

1. **Ingest** security events from JSONL.
2. **Validate** the event structure and preserve the original evidence.
3. **Detect** suspicious patterns using explicit rules.
4. **Score** findings using transparent risk logic.
5. **Enrich** observables from safe local context.
6. **Correlate** related findings into deterministic analyst cases.
7. **Report** the result as Markdown and structured JSON.

The system produces analyst guidance from the available evidence; it does **not** claim to replace analyst judgment or predict incidents with certainty.

## 🔐 Security & Responsible Use

AI SOC Copilot is intentionally defensive and local-first.

- No arbitrary command execution
- No exploitation functionality
- No external calls by default
- Synthetic sample data only
- Strict input validation
- Safe local enrichment boundaries
- Secrets excluded from source control
- Security-focused tests and CI checks

> Use the project with authorized security data and environments only.

## 🚀 Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

python -m ai_soc_copilot.cli \
  --input samples/security_events.jsonl \
  --output reports/incident_report.md \
  --case-json reports/cases.json
```

Example result:

```text
Processed events: 5
Findings: 5
Cases: 4
Markdown report written to reports/incident_report.md
Structured cases written to reports/cases.json
```

## 🧱 Built With

- **Python 3.11+**
- Dataclasses
- `argparse`
- JSONL / JSON
- `pytest`
- Markdown
- Mermaid

## 🏅 Engineering Quality

The project uses automated **CI, validation tests, strict input handling, and security-focused engineering practices** to keep the detection and triage pipeline reproducible.

## 📁 Project Structure

```text
src/ai_soc_copilot/
├── parser.py        # Input validation
├── detection.py     # Detection rules
├── triage.py        # Risk and prioritization
├── enrichment.py    # Local enrichment
├── case_builder.py  # Case correlation
├── report.py        # Report generation
├── models.py        # Domain models
└── cli.py            # CLI
```

## 🔭 Vision

AI SOC Copilot aims to become a practical **analyst-assistance layer for defensive security operations** — helping teams move from raw alerts to explainable findings, organized cases, and actionable next steps.

## 🤝 Contributing

Contributions, detection ideas, test cases, and improvements are welcome.

---

<p align="center">
  <strong>AI SOC Copilot</strong><br>
  <em>From alert noise to analyst clarity.</em>
</p>
