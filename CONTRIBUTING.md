# Contributing to G1 RedTeam

Thank you for your interest in contributing to **G1 RedTeam** by G1163RT Security Labs.

## Development Setup

### Prerequisites
- Python 3.10+
- Node.js 20+ and `npm`
- Docker & Docker Compose (for full-stack integration testing)

### Local Components

1. **Python SDK (`g1163rt-sdk`)**
   ```bash
   pip install -e ./g1163rt-sdk[dev]
   pytest g1163rt-sdk/tests
   ```

2. **Threat Transpiler (`threat-transpiler`)**
   ```bash
   pip install -e ./threat-transpiler
   pytest threat-transpiler/tests
   ```

3. **SaaS Control Plane Dashboard (`saas-dashboard`)**
   ```bash
   cd saas-dashboard
   npm install
   npm run dev
   ```

4. **Full-Stack Docker Verification**
   ```bash
   docker compose up --build -d
   python hybrid-runner/verify_updates.py --url http://localhost:3000 --skip-billing
   ```

## Architectural Invariants

When submitting pull requests, please preserve these core guarantees:
- **Zero-Data-Retention Boundary:** Customer prompts, model completions, and target gateway API keys must remain inside the local VPC runner execution path.
- **Permissive Open-Source Hygiene:** Any newly integrated evaluation engine or dependency must be permissively licensed (Apache-2.0, MIT, BSD) and documented in [`attribution.md`](attribution.md).
- **No Secrets or Runtime Artifacts:** Never commit `.env` files, API keys, `jobs_db.json`, `.runner_id`, or generated `.zip` bundles.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Ensure unit tests (`pytest`) and dashboard linting (`npm run lint`) pass.
3. Submit a pull request describing the change, motivation, and verification steps.
