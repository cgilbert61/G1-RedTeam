# Security Policy

## Supported Versions

G1 RedTeam is actively maintained on the `main` branch. Security fixes are applied to the latest release of each component (`hybrid-runner`, `saas-dashboard`, `threat-transpiler`, and `g1163rt-sdk`).

| Component | Supported |
| :--- | :---: |
| `main` branch (latest) | :white_check_mark: |
| Older snapshots / forks | :x: |

## Reporting a Vulnerability

If you discover a security vulnerability in G1 RedTeam — including authentication bypasses, runner isolation flaws, dependency vulnerabilities, or credential leakage — please report it responsibly rather than opening a public GitHub issue.

- **Email:** `security@g1163rt.ai`
- **Include:** Affected component/file path, reproduction steps or proof-of-concept, potential impact, and any suggested remediation.

### Response Timeline

1. **Acknowledgment:** Within 48 hours of receipt.
2. **Triage & Assessment:** Within 5 business days.
3. **Coordinated Remediation:** Patches are developed and validated prior to public disclosure.

## Zero-Data-Retention Security Boundary

By design, `hybrid-runner` executes all adversarial probes, LLM-as-a-judge calls, and MCP tool evaluations inside the customer's private VPC. Never commit live API keys, `.env` files, `jobs_db.json`, or target gateway credentials to this repository.
