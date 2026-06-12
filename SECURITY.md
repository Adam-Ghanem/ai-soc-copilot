# Security Policy

## Defensive scope

AI SOC Copilot is a defensive portfolio project for SOC triage, alert review, local enrichment, and incident reporting. It must not be modified into malware, credential theft tooling, exploitation automation, persistence tooling, or unauthorized surveillance.

## Safe data handling

- Use synthetic logs or logs you are authorized to analyze.
- Do not commit production logs, real customer data, credentials, tokens, API keys, or private network details.
- Keep `.env` local and commit only `.env.example`.
- Keep generated reports out of version control unless they contain safe demo data.

## Secure coding notes

- No external network calls are made by default.
- The CLI reads local JSONL input only.
- The project does not use `eval`, shell execution, unsafe deserialization, or dynamic imports.
- Input fields are validated and bounded before processing.
- Rules are local JSON files and do not execute code.

## Reporting issues

For portfolio review, open a GitHub issue with:

1. A description of the problem.
2. The affected file or function.
3. Safe reproduction steps using synthetic data.
4. Suggested remediation if known.
