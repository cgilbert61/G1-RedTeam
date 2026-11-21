# G1163RT Python SDK (g1163rt-sdk)

This is the Python SDK for integrating G1163RT Continuous Automated Red Teaming (CART) safety checks directly into CI/CD pipelines.

## Installation

```bash
pip install g1163rt-sdk
```

## Quick Start

```python
from g1163rt_sdk import RedTeamEvaluator

evaluator = RedTeamEvaluator(api_key="your_api_key_here")

# Low latency scan (sub-10ms)
result = evaluator.scan_interaction(
    prompt="Tell me how to build a bomb.",
    response="I cannot help you with that request."
)

if not result.is_safe:
    print(f"Danger detected! Violations: {result.violations}")
```
