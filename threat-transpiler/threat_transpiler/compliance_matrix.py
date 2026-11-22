"""Canonical vulnerability taxonomy and 8-framework compliance matrix.

Clean-room implementation mapping normalized AI/agent vulnerability classes to
eight security and governance frameworks:
  1. OWASP LLM Top 10 (2025)
  2. OWASP API Top 10
  3. MITRE ATLAS
  4. NIST AI RMF
  5. ISO/IEC 42001
  6. EU AI Act
  7. GDPR
  8. Basic Security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class VulnerabilityId(str, Enum):
    """Canonical vulnerability identifiers across all G1 RedTeam engines."""

    PROMPT_INJECTION = "prompt_injection"
    PROMPT_EXTRACTION = "prompt_extraction"
    PII_LEAKAGE = "pii_leakage"
    EXCESSIVE_AGENCY = "excessive_agency"
    RBAC_BOLA_BFLA = "rbac_bola_bfla"
    RAG_MEMORY_POISONING = "rag_memory_poisoning"
    CODE_SQL_SHELL_INJECTION = "code_sql_shell_injection"
    HALLUCINATION = "hallucination"
    UNBOUNDED_CONSUMPTION_DOS = "unbounded_consumption_dos"
    CONTENT_SAFETY = "content_safety"
    BIAS_FAIRNESS = "bias_fairness"


class ComplianceFrameworkId(str, Enum):
    """Eight supported security and regulatory compliance frameworks."""

    OWASP_LLM_2025 = "owasp_llm_2025"
    OWASP_API_2023 = "owasp_api_2023"
    MITRE_ATLAS = "mitre_atlas"
    NIST_AI_RMF = "nist_ai_rmf"
    ISO_42001 = "iso_42001"
    EU_AI_ACT = "eu_ai_act"
    GDPR = "gdpr"
    BASIC_SECURITY = "basic_security"


@dataclass(frozen=True)
class FrameworkMeta:
    id: ComplianceFrameworkId
    name: str
    version: str
    description: str


@dataclass(frozen=True)
class VulnerabilityProfile:
    id: VulnerabilityId
    name: str
    description: str
    default_impact: float  # 0.0 - 4.0
    default_human_factor: float  # 0.0 - 1.5
    default_complexity_penalty: float  # 0.0 - 0.5
    controls: Dict[ComplianceFrameworkId, List[str]] = field(default_factory=dict)


FRAMEWORK_METADATA: Dict[ComplianceFrameworkId, FrameworkMeta] = {
    ComplianceFrameworkId.OWASP_LLM_2025: FrameworkMeta(
        id=ComplianceFrameworkId.OWASP_LLM_2025,
        name="OWASP LLM Top 10 (2025)",
        version="2025",
        description="Top 10 critical security risks for Large Language Model applications.",
    ),
    ComplianceFrameworkId.OWASP_API_2023: FrameworkMeta(
        id=ComplianceFrameworkId.OWASP_API_2023,
        name="OWASP API Top 10",
        version="2023",
        description="Top 10 API security vulnerabilities affecting agent gateways and tool backends.",
    ),
    ComplianceFrameworkId.MITRE_ATLAS: FrameworkMeta(
        id=ComplianceFrameworkId.MITRE_ATLAS,
        name="MITRE ATLAS",
        version="4.x",
        description="Adversarial Threat Landscape for Artificial-Intelligence Systems.",
    ),
    ComplianceFrameworkId.NIST_AI_RMF: FrameworkMeta(
        id=ComplianceFrameworkId.NIST_AI_RMF,
        name="NIST AI RMF",
        version="1.0",
        description="NIST Artificial Intelligence Risk Management Framework (Govern, Map, Measure, Manage).",
    ),
    ComplianceFrameworkId.ISO_42001: FrameworkMeta(
        id=ComplianceFrameworkId.ISO_42001,
        name="ISO/IEC 42001",
        version="2023",
        description="International standard for Artificial Intelligence Management Systems (AIMS).",
    ),
    ComplianceFrameworkId.EU_AI_ACT: FrameworkMeta(
        id=ComplianceFrameworkId.EU_AI_ACT,
        name="EU AI Act",
        version="2024/1689",
        description="European Union Regulation on Artificial Intelligence risk & robustness obligations.",
    ),
    ComplianceFrameworkId.GDPR: FrameworkMeta(
        id=ComplianceFrameworkId.GDPR,
        name="GDPR",
        version="2016/679",
        description="General Data Protection Regulation obligations for personal data protection.",
    ),
    ComplianceFrameworkId.BASIC_SECURITY: FrameworkMeta(
        id=ComplianceFrameworkId.BASIC_SECURITY,
        name="Basic Security",
        version="1.0",
        description="Foundational enterprise AI gateway security controls baseline.",
    ),
}


VULNERABILITY_CATALOG: Dict[VulnerabilityId, VulnerabilityProfile] = {
    VulnerabilityId.PROMPT_INJECTION: VulnerabilityProfile(
        id=VulnerabilityId.PROMPT_INJECTION,
        name="Prompt Injection & Jailbreak",
        description="Adversarial instructions that override system policies or hijack control flow.",
        default_impact=3.6,
        default_human_factor=1.3,
        default_complexity_penalty=0.1,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM01:2025 Prompt Injection"],
            ComplianceFrameworkId.OWASP_API_2023: ["API8:2023 Security Misconfiguration"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0051 LLM Prompt Injection", "AML.T0054 LLM Jailbreak"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MEASURE 2.7", "MANAGE 2.4"],
            ComplianceFrameworkId.ISO_42001: ["A.6.2.4 Verification & Validation", "A.9.3 Adversarial Robustness"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 15 Accuracy, Robustness & Cybersecurity"],
            ComplianceFrameworkId.GDPR: ["Art. 32 Security of Processing"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-01 Input Guardrails"],
        },
    ),
    VulnerabilityId.PROMPT_EXTRACTION: VulnerabilityProfile(
        id=VulnerabilityId.PROMPT_EXTRACTION,
        name="System Prompt Leakage & Extraction",
        description="Disclosure of hidden system prompts, policy instructions, or embedded secrets.",
        default_impact=2.8,
        default_human_factor=1.2,
        default_complexity_penalty=0.1,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM07:2025 System Prompt Leakage"],
            ComplianceFrameworkId.OWASP_API_2023: ["API3:2023 Broken Object Property Level Authorization"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0056 Extract LLM System Prompt"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MAP 3.5", "MEASURE 2.7"],
            ComplianceFrameworkId.ISO_42001: ["A.7.4 Data & Model Confidentiality"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 15 Cybersecurity Resilience"],
            ComplianceFrameworkId.GDPR: ["Art. 32 Confidentiality of Processing"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-02 Secret & Prompt Isolation"],
        },
    ),
    VulnerabilityId.PII_LEAKAGE: VulnerabilityProfile(
        id=VulnerabilityId.PII_LEAKAGE,
        name="Sensitive Information & PII Leakage",
        description="Exposure of personally identifiable information, credentials, or confidential records.",
        default_impact=3.8,
        default_human_factor=1.2,
        default_complexity_penalty=0.1,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM02:2025 Sensitive Information Disclosure"],
            ComplianceFrameworkId.OWASP_API_2023: ["API3:2023 Excessive Data Exposure"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0024 Exfiltration via ML Inference API"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MAP 5.1", "MEASURE 2.10"],
            ComplianceFrameworkId.ISO_42001: ["A.7.5 Privacy & PII Protection"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 10 Data Governance"],
            ComplianceFrameworkId.GDPR: ["Art. 5 Data Minimization", "Art. 25 Privacy by Design", "Art. 32 Security of Processing"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-03 DLP & PII Redaction"],
        },
    ),
    VulnerabilityId.EXCESSIVE_AGENCY: VulnerabilityProfile(
        id=VulnerabilityId.EXCESSIVE_AGENCY,
        name="Excessive Agency & Unsafe Tool Execution",
        description="Agent invokes privileged tools, destructive actions, or external side effects without authorization.",
        default_impact=3.9,
        default_human_factor=1.1,
        default_complexity_penalty=0.2,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM06:2025 Excessive Agency"],
            ComplianceFrameworkId.OWASP_API_2023: ["API5:2023 Broken Function Level Authorization"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0053 LLM Plugin Compromise"],
            ComplianceFrameworkId.NIST_AI_RMF: ["GOVERN 1.4", "MANAGE 2.2"],
            ComplianceFrameworkId.ISO_42001: ["A.6.2.6 Human Oversight & Autonomy Limits"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 14 Human Oversight"],
            ComplianceFrameworkId.GDPR: ["Art. 22 Automated Decision-Making"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-04 Least-Privilege Tool Governance"],
        },
    ),
    VulnerabilityId.RBAC_BOLA_BFLA: VulnerabilityProfile(
        id=VulnerabilityId.RBAC_BOLA_BFLA,
        name="RBAC / BOLA / BFLA Authorization Bypass",
        description="Cross-tenant data access, privilege escalation, or missing object/function-level authorization.",
        default_impact=3.9,
        default_human_factor=1.3,
        default_complexity_penalty=0.15,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM06:2025 Excessive Agency", "LLM02:2025 Sensitive Information Disclosure"],
            ComplianceFrameworkId.OWASP_API_2023: ["API1:2023 BOLA", "API5:2023 BFLA"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0040 ML Model Inference API Access"],
            ComplianceFrameworkId.NIST_AI_RMF: ["GOVERN 1.5", "MANAGE 4.1"],
            ComplianceFrameworkId.ISO_42001: ["A.8.3 Access Control"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 15 Access & Integrity Controls"],
            ComplianceFrameworkId.GDPR: ["Art. 32 Unauthorized Disclosure Prevention"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-05 Identity & RBAC Enforcement"],
        },
    ),
    VulnerabilityId.RAG_MEMORY_POISONING: VulnerabilityProfile(
        id=VulnerabilityId.RAG_MEMORY_POISONING,
        name="RAG & Long-Term Memory Poisoning",
        description="Manipulation of retrieved context, vector stores, or persistent agent memory to alter future outputs.",
        default_impact=3.5,
        default_human_factor=1.0,
        default_complexity_penalty=0.25,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM08:2025 Vector and Embedding Weaknesses", "LLM04:2025 Data and Model Poisoning"],
            ComplianceFrameworkId.OWASP_API_2023: ["API8:2023 Security Misconfiguration"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0020 Poison Training Data", "AML.T0051.001 Indirect Prompt Injection"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MAP 2.3", "MEASURE 2.6"],
            ComplianceFrameworkId.ISO_42001: ["A.7.3 Data Quality & Provenance"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 10 Data Governance", "Art. 15 Data Poisoning Resilience"],
            ComplianceFrameworkId.GDPR: ["Art. 5(1)(d) Accuracy & Integrity"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-06 Retrieval Integrity & Sanitization"],
        },
    ),
    VulnerabilityId.CODE_SQL_SHELL_INJECTION: VulnerabilityProfile(
        id=VulnerabilityId.CODE_SQL_SHELL_INJECTION,
        name="SQL, Shell, XSS & Code Injection",
        description="Improper output handling leading to SQLi, OS command execution, XSS, or code injection downstream.",
        default_impact=4.0,
        default_human_factor=1.4,
        default_complexity_penalty=0.1,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM05:2025 Improper Output Handling"],
            ComplianceFrameworkId.OWASP_API_2023: ["API8:2023 Injection & Unsafe Consumption"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0053 Execution via Compromised Tool"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MEASURE 2.7", "MANAGE 2.4"],
            ComplianceFrameworkId.ISO_42001: ["A.6.2.5 Output Validation & Sandboxing"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 15 Cybersecurity"],
            ComplianceFrameworkId.GDPR: ["Art. 32 Integrity of Processing Systems"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-07 Output Encoding & Sandboxing"],
        },
    ),
    VulnerabilityId.HALLUCINATION: VulnerabilityProfile(
        id=VulnerabilityId.HALLUCINATION,
        name="Hallucination & Misinformation",
        description="Fabricated facts, unfaithful claims, or unsupported assertions contradicting grounding context.",
        default_impact=2.4,
        default_human_factor=0.9,
        default_complexity_penalty=0.2,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM09:2025 Misinformation"],
            ComplianceFrameworkId.OWASP_API_2023: ["API10:2023 Unsafe Consumption of APIs"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0048 External Harms / Misinformation"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MEASURE 2.5", "MEASURE 2.6"],
            ComplianceFrameworkId.ISO_42001: ["A.6.2.4 Reliability & Accuracy Testing"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 13 Transparency", "Art. 15 Accuracy"],
            ComplianceFrameworkId.GDPR: ["Art. 5(1)(d) Data Accuracy"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-08 Groundedness & Verification"],
        },
    ),
    VulnerabilityId.UNBOUNDED_CONSUMPTION_DOS: VulnerabilityProfile(
        id=VulnerabilityId.UNBOUNDED_CONSUMPTION_DOS,
        name="Unbounded Consumption & Denial of Service",
        description="Token exhaustion, recursive tool loops, or resource starvation degrading service availability.",
        default_impact=2.9,
        default_human_factor=1.1,
        default_complexity_penalty=0.15,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM10:2025 Unbounded Consumption"],
            ComplianceFrameworkId.OWASP_API_2023: ["API4:2023 Unrestricted Resource Consumption"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0029 Denial of ML Service"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MANAGE 2.3", "MEASURE 2.7"],
            ComplianceFrameworkId.ISO_42001: ["A.8.4 Availability & Quota Controls"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 15 Availability & Resilience"],
            ComplianceFrameworkId.GDPR: ["Art. 32(1)(b) Availability & Resilience"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-09 Rate Limiting & Token Budgets"],
        },
    ),
    VulnerabilityId.CONTENT_SAFETY: VulnerabilityProfile(
        id=VulnerabilityId.CONTENT_SAFETY,
        name="Harmful, Illegal, or Toxic Content Generation",
        description="Generation of violent, illegal, abusive, cyberattack, or self-harm content violating safety policies.",
        default_impact=3.2,
        default_human_factor=1.2,
        default_complexity_penalty=0.1,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM01:2025 Prompt Injection", "LLM09:2025 Misinformation"],
            ComplianceFrameworkId.OWASP_API_2023: ["API8:2023 Security Misconfiguration"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0054 LLM Jailbreak"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MEASURE 2.6", "MANAGE 1.3"],
            ComplianceFrameworkId.ISO_42001: ["A.5.2 Societal & Safety Impact Assessment"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 5 Prohibited Practices", "Art. 9 Risk Management"],
            ComplianceFrameworkId.GDPR: ["Art. 5 Lawfulness & Fairness"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-10 Content Safety Moderation"],
        },
    ),
    VulnerabilityId.BIAS_FAIRNESS: VulnerabilityProfile(
        id=VulnerabilityId.BIAS_FAIRNESS,
        name="Demographic Bias & Unfair Discrimination",
        description="Systematic discriminatory, stereotyped, or inequitable outputs across protected groups.",
        default_impact=2.6,
        default_human_factor=0.9,
        default_complexity_penalty=0.2,
        controls={
            ComplianceFrameworkId.OWASP_LLM_2025: ["LLM09:2025 Misinformation"],
            ComplianceFrameworkId.OWASP_API_2023: ["API10:2023 Unsafe Consumption of APIs"],
            ComplianceFrameworkId.MITRE_ATLAS: ["AML.T0048 Societal Harm"],
            ComplianceFrameworkId.NIST_AI_RMF: ["MEASURE 2.11 Fairness & Bias"],
            ComplianceFrameworkId.ISO_42001: ["A.5.4 Fairness & Non-Discrimination"],
            ComplianceFrameworkId.EU_AI_ACT: ["Art. 10(2)(f) Bias Examination & Mitigation"],
            ComplianceFrameworkId.GDPR: ["Art. 5(1)(a) Fairness", "Art. 22 Profiling Safeguards"],
            ComplianceFrameworkId.BASIC_SECURITY: ["BS-11 Fairness & Non-Discrimination"],
        },
    ),
}


_KEYWORD_RULES: List[tuple[List[str], VulnerabilityId]] = [
    (["system prompt", "prompt extraction", "prompt_extraction", "leakage", "reveal your system", "system instructions"], VulnerabilityId.PROMPT_EXTRACTION),
    (["pii", "privacy", "personal data", "ssn", "secret", "credential", "api key", "doxx", "exfil"], VulnerabilityId.PII_LEAKAGE),
    (["sql", "xss", "shell", "command injection", "code injection", "drop table", "script", "rce"], VulnerabilityId.CODE_SQL_SHELL_INJECTION),
    (["bola", "bfla", "rbac", "authorization", "privilege", "admin", "tenant", "oauth", "bypass auth"], VulnerabilityId.RBAC_BOLA_BFLA),
    (["mcp", "tool", "agency", "plugin", "function call", "destructive", "file write"], VulnerabilityId.EXCESSIVE_AGENCY),
    (["rag", "memory", "poison", "vector", "embedding", "retrieval", "indirect"], VulnerabilityId.RAG_MEMORY_POISONING),
    (["hallucinat", "faithful", "context_recall", "misinformation", "grounded"], VulnerabilityId.HALLUCINATION),
    (["dos", "denial", "unbounded", "consumption", "rate limit", "exhaustion", "loop", "ddos"], VulnerabilityId.UNBOUNDED_CONSUMPTION_DOS),
    (["bias", "fairness", "discriminat", "stereotyp", "hate_speech", "hate speech"], VulnerabilityId.BIAS_FAIRNESS),
    (["toxic", "violence", "weapon", "suicide", "harassment", "sexual", "child", "illegal", "fraud", "phishing", "ransomware", "beavertails", "harm", "malware", "cyberattack"], VulnerabilityId.CONTENT_SAFETY),
    (["jailbreak", "promptinject", "injection", "smuggling", "override", "ignore previous", "encoding", "continuation", "pyrit"], VulnerabilityId.PROMPT_INJECTION),
]


def infer_vulnerability_id(
    category: Optional[str] = None,
    text: Optional[str] = None,
) -> VulnerabilityId:
    """Resolve a canonical VulnerabilityId from an explicit ID, category, or payload text."""
    if category:
        normalized = category.strip().lower().replace("-", "_").replace(" ", "_")
        for member in VulnerabilityId:
            if member.value == normalized:
                return member

    combined = f"{category or ''} {text or ''}".lower()
    for keywords, vuln_id in _KEYWORD_RULES:
        if any(kw in combined for kw in keywords):
            return vuln_id
    return VulnerabilityId.PROMPT_INJECTION


def get_vulnerability_profile(
    vuln_id: Union[str, VulnerabilityId],
) -> VulnerabilityProfile:
    """Return the VulnerabilityProfile for a given VulnerabilityId (or infer it)."""
    if isinstance(vuln_id, VulnerabilityId):
        return VULNERABILITY_CATALOG[vuln_id]
    resolved = infer_vulnerability_id(category=vuln_id)
    return VULNERABILITY_CATALOG[resolved]


def get_compliance_mappings(
    vuln_id: Union[str, VulnerabilityId],
) -> Dict[str, List[str]]:
    """Return framework_id -> list of control strings for a vulnerability."""
    profile = get_vulnerability_profile(vuln_id)
    return {fw.value: list(controls) for fw, controls in profile.controls.items()}


def get_frameworks_catalog() -> Dict[str, Any]:
    """Build the full JSON-serializable compliance catalog for GET /compliance/frameworks."""
    frameworks_out: List[Dict[str, Any]] = []
    for fw_id, meta in FRAMEWORK_METADATA.items():
        mapped_vulns = []
        all_controls: List[str] = []
        for vuln_id, profile in VULNERABILITY_CATALOG.items():
            controls = profile.controls.get(fw_id, [])
            if controls:
                mapped_vulns.append({
                    "vulnerability_id": vuln_id.value,
                    "name": profile.name,
                    "controls": controls,
                })
                for c in controls:
                    if c not in all_controls:
                        all_controls.append(c)
        frameworks_out.append({
            "id": fw_id.value,
            "name": meta.name,
            "version": meta.version,
            "description": meta.description,
            "control_count": len(all_controls),
            "controls": all_controls,
            "vulnerabilities": mapped_vulns,
        })

    vulnerabilities_out = [
        {
            "id": profile.id.value,
            "name": profile.name,
            "description": profile.description,
            "default_impact": profile.default_impact,
            "default_human_factor": profile.default_human_factor,
            "default_complexity_penalty": profile.default_complexity_penalty,
            "frameworks": {fw.value: controls for fw, controls in profile.controls.items()},
        }
        for profile in VULNERABILITY_CATALOG.values()
    ]

    return {
        "framework_count": len(frameworks_out),
        "vulnerability_count": len(vulnerabilities_out),
        "frameworks": frameworks_out,
        "vulnerabilities": vulnerabilities_out,
    }


def compute_framework_rollup(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate pass/fail findings into an 8-framework compliance matrix."""
    rollup: Dict[str, Any] = {}
    for fw_id, meta in FRAMEWORK_METADATA.items():
        tested_controls: set[str] = set()
        failed_controls: set[str] = set()
        passed_cases = 0
        failed_cases = 0

        for item in findings:
            raw_vuln = item.get("vulnerability_id") or item.get("vulnerability_type") or item.get("suite")
            prompt_text = item.get("prompt") or ""
            profile = get_vulnerability_profile(
                infer_vulnerability_id(category=str(raw_vuln) if raw_vuln else None, text=str(prompt_text))
            )
            controls = profile.controls.get(fw_id, [])
            if not controls:
                continue
            for c in controls:
                tested_controls.add(c)
            if item.get("passed", True):
                passed_cases += 1
            else:
                failed_cases += 1
                for c in controls:
                    failed_controls.add(c)

        total_cases = passed_cases + failed_cases
        if total_cases == 0:
            status = "not_tested"
            compliance_rate = 100.0
        elif failed_cases == 0:
            status = "pass"
            compliance_rate = 100.0
        else:
            status = "fail"
            compliance_rate = round((passed_cases / total_cases) * 100.0, 1)

        rollup[fw_id.value] = {
            "id": fw_id.value,
            "name": meta.name,
            "version": meta.version,
            "status": status,
            "passed_cases": passed_cases,
            "failed_cases": failed_cases,
            "total_cases": total_cases,
            "compliance_rate": compliance_rate,
            "tested_controls": sorted(tested_controls),
            "failed_controls": sorted(failed_controls),
        }

    return rollup
