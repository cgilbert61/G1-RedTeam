# G1163RT AI Red Teaming Platform — CLI Commands Reference

This document compiles the command-line interfaces (CLIs), background runner configurations, and orchestration commands used across the G1163RT AI Red Teaming platform.

---

## 1. Threat Intel Verification Test Runner (`verify_updates.py`)

The verification script validates the threat intelligence update channels, subscription validation logic, and authentication constraints.

### Usage
```bash
python hybrid-runner/verify_updates.py [options]
```

### Command Options
| Flag / Option | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `-u`, `--url` | `SAAS_URL` | `http://localhost:3001` | Base URL of the SaaS / Control Plane dashboard. |
| `-k`, `--key` | `INTEL_API_KEY` | `ent_key_secops_wallstreet_9921` | Enterprise authorization bearer key to authenticate and pull rules. |
| `--skip-billing` | — | `False` (disabled) | Skip the billing status validation test (`expired_key`) to prevent modifying active DB subscription flags on shared environments. |
| `--junit PATH` | — | — | Path where a standardized JUnit XML test results report should be saved. |
| `-t`, `--test` | — | — | Run only a single specific test case: `missing_auth`, `invalid_auth`, `active_key`, or `expired_key`. |
| `--pyrit-turns` | — | `5` | Set the maximum fuzzing interaction turns for simulated PyRIT scans. |
| `--deepeval-metrics` | — | `toxicity faithfulness context_recall` | Specify a space-separated list of DeepEval LLM-as-a-Judge validation metrics. |

### Execution Examples
* **Run full suite with a custom URL:**
  ```bash
  python hybrid-runner/verify_updates.py --url http://localhost:3000
  ```
* **Run a single test case without affecting billing status, exporting results to JUnit:**
  ```bash
  python hybrid-runner/verify_updates.py --test active_key --skip-billing --junit report.xml
  ```
* **Verify with custom PyRIT limits and DeepEval scorers:**
  ```bash
  python hybrid-runner/verify_updates.py --pyrit-turns 10 --deepeval-metrics toxicity faithfulness
  ```

---

## 2. Hybrid Agent Runner Daemon (`main.py`)

The runner daemon is a persistent loop that coordinates job execution, pulls signature updates, and queries target models.

### Usage
```bash
python hybrid-runner/main.py
```

### Configuration Environment Variables
The daemon does not parse direct command flags, but reads from shell environment variables (mapped in `config.py`):

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SAAS_URL` | `http://localhost:3001` | Base control plane API endpoint for control handshake. |
| `POLL_INTERVAL` | `5` | The queue check frequency in seconds. |
| `INTEL_API_KEY` | `ent_key_secops_wallstreet_9921` | Bearer credential utilized by the thread checking for daily rule signature updates. |

### Runtime Lifecycle
1. Checks connection health with the SaaS database control plane.
2. Spawns a background thread to check for new threat intelligence signatures from `/api/intel` every 24 hours.
3. Polls the control queue for pending scan jobs.
4. Spawns child fuzzing workers (Garak, Promptfoo, PyRIT, DeepEval, MCP) to probe target gateways and returns compiled reports.

---

## 3. Stack Orchestration (`docker-compose`)

Orchestrate the entire platform (SaaS Dashboard, Runner, and Mock Gateways) using Docker Compose.

### Build and Start Stack
Build all Dockerfiles and start containerized services in the background:
```bash
docker-compose up --build -d
```

### Stop and Teardown Stack
Stop active containers and clean networks:
```bash
docker-compose down
```

### Service Logs
Tail container stdout/stderr logs:
* **All Services:**
  ```bash
  docker-compose logs -f
  ```
* **Runner Daemon Only:**
  ```bash
  docker-compose logs -f hybrid-runner
  ```
* **Control Plane Dashboard Only:**
  ```bash
  docker-compose logs -f saas-dashboard
  ```

### Inspect Container Port Mappings
View active network links and health statuses:
```bash
docker-compose ps
```

---

## 4. Distribution Packager (`repackage_zip.py`)

Compresses the verified on-premise application stack into a standardized installer package.

### Usage
```bash
python scratch/repackage_zip.py
```

### Description
Excludes heavy build and development caches (e.g. `node_modules`, `.next`, `__pycache__`) and outputs a clean containerized package file [`g1163rt-agent-onprem.zip`](file:///c:/Users/chuck/redteam/public-dist/g1163rt-agent-onprem.zip) (~132 KB) to public distribution targets.
