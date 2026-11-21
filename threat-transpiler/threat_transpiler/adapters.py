import re
import json
from typing import Dict, Any, List
from threat_transpiler.schema import IRPayload

class RegexWAFAdapter:
    """
    Compiles normalized threat tokens and structures into high-performance,
    ReDoS-safe PCRE regular expressions.
    """

    @classmethod
    def check_redos_risk(cls, pattern: str) -> bool:
        """
        Validates a regex pattern to detect dangerous ReDoS conditions
        such as nested quantifiers (e.g. (a+)+, (a*)*) or overlapping options.
        """
        # Look for nested quantifiers: *, +, {n,m} applied to a group that already has one
        nested_quantifier_pattern = re.compile(
            r'\([^)]*[*+{][^)]*\)[*+{]'
        )
        if nested_quantifier_pattern.search(pattern):
            return True
        
        # Look for wildcards with no upper bounds adjacent to other quantifiers
        if ".*.*" in pattern or ".+.+" in pattern:
            return True
            
        return False

    @classmethod
    def compile(cls, payload: IRPayload) -> str:
        """
        Generates a ReDoS-protected PCRE pattern from the IR payload tokens and text.
        """
        # Escape any special characters in tokens to prevent regex injection
        escaped_tokens = [re.escape(t) for t in payload.tokens if t]
        
        if not escaped_tokens:
            # Fallback to escaping canonical text with bounded wildcard spacing
            escaped_text = re.escape(payload.canonical_text)
            # Replace spaces with bounded whitespace match to prevent ReDoS on massive spaces
            pattern = re.sub(r'\\ ', r'\\s{1,5}', escaped_text)
        else:
            # Create a token sequence matching group with bounded spaces
            token_sequence = r"\s{1,5}".join(escaped_tokens)
            pattern = rf"\b{token_sequence}\b"

        # Apply maximum length safety to prevent massive backtracking
        # Replace any open .* with a bounded length quantifier
        pattern = pattern.replace(".*", ".{0,200}")
        pattern = pattern.replace(".+", ".{1,200}")

        # Final safety check
        if cls.check_redos_risk(pattern):
            # If ReDoS risk detected, fall back to literal token bounds without complex grouping
            clean_tokens = [re.sub(r'[^a-zA-Z0-9]', '', t) for t in payload.tokens]
            clean_tokens = [t for t in clean_tokens if t]
            if clean_tokens:
                token_seq = r'\s{1,5}'.join(clean_tokens)
                pattern = rf"\b{token_seq}\b"
            else:
                pattern = re.escape(payload.canonical_text)[:100]

        return pattern


class OPARegoAdapter:
    """
    Emits valid Rego policy blocks for contextual state and input validation in OPA.
    """

    @classmethod
    def compile(cls, payload: IRPayload) -> str:
        """
        Emits valid Rego code enforcing structural constraints and matching the compiled regex signature.
        """
        threat_id_clean = re.sub(r'[^a-zA-Z0-9_]', '_', payload.threat_id)
        category_clean = re.sub(r'[^a-zA-Z0-9_]', '_', payload.category)
        
        # Determine threshold/limits from constraints or fall back to defaults
        max_messages = int(payload.constraints.get("max_messages", 10))
        allowed_roles = payload.constraints.get("allowed_roles", ["user", "assistant", "system"])
        # Format roles array for Rego
        rego_roles = ", ".join([f'"{r}"' for r in allowed_roles])
        
        # Compile regex pattern using RegexAdapter
        regex_pattern = RegexWAFAdapter.compile(payload)
        # Rego backslash escape helper
        rego_regex = regex_pattern.replace('\\', '\\\\').replace('"', '\\"')

        rego_template = f"""package play.security.threat_detection.{category_clean}

# Default denies authorization if threat is detected
default allow = false
default violation = false

# Allow traffic if no violation rule triggers
allow {{
    not violation
}}

# Violation Rule 1: Structural message count boundary check
violation {{
    input.messages
    count(input.messages) > {max_messages}
}}

# Violation Rule 2: Message role structure validity check
violation {{
    some i
    msg := input.messages[i]
    valid_roles := {{{rego_roles}}}
    not valid_roles[msg.role]
}}

# Violation Rule 3: Text signature validation matching threat: {threat_id_clean}
violation {{
    some i
    msg := input.messages[i]
    msg.content
    re_match("{rego_regex}", msg.content)
}}
"""
        return rego_template


class JSONSchemaAdapter:
    """
    Generates Draft-07 JSON Schema templates for validation gateways
    to prevent smuggling of long instructions or malformed payloads.
    """

    @classmethod
    def compile(cls, payload: IRPayload) -> Dict[str, Any]:
        """
        Builds the JSON schema mapping constraints.
        """
        # Fetch parameter constraints
        max_length = int(payload.constraints.get("max_length", 2048))
        min_length = int(payload.constraints.get("min_length", 1))
        
        # Generate regex constraint
        regex_pattern = RegexWAFAdapter.compile(payload)

        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": f"ThreatValidationSchema_{payload.threat_id}",
            "description": f"Enforces parameter boundaries against threat category: {payload.category}",
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "minLength": min_length,
                    "maxLength": max_length,
                    "not": {
                        "pattern": regex_pattern
                    }
                }
            },
            "required": ["prompt"],
            "additionalProperties": True
        }
        return schema


class SemanticVectorAdapter:
    """
    Formats embedding vector updates representing threat centroids
    for ingestion into Milvus/Qdrant vector firewalls.
    """

    @classmethod
    def compile(cls, payload: IRPayload) -> Dict[str, Any]:
        """
        Builds a unified vector record format containing dimension metadata
        and similarity thresholds.
        """
        # Fetch distance metric (default to Cosine) and threshold
        distance_metric = str(payload.constraints.get("distance_metric", "Cosine"))
        similarity_threshold = float(payload.constraints.get("similarity_threshold", 0.85))

        # Enforce that centroids exist
        if not payload.centroids:
            raise ValueError(f"Centroid embeddings are required for SemanticVectorAdapter. Threat ID: {payload.threat_id}")

        vector_payload = {
            "threat_id": payload.threat_id,
            "category": payload.category,
            "vector": payload.centroids,
            "dimension": len(payload.centroids),
            "distance_metric": distance_metric,
            "similarity_threshold": similarity_threshold,
            "metadata": {
                "source": payload.metadata.get("source", "automated_threat_feed"),
                "confidence": float(payload.metadata.get("confidence", 1.0)),
                "canonical_text_truncated": payload.canonical_text[:200]
            }
        }
        return vector_payload
