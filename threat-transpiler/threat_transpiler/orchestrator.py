import time
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from threat_transpiler.schema import IRPayload
from threat_transpiler.normalizer import ThreatNormalizer
from threat_transpiler.adapters import (
    RegexWAFAdapter,
    OPARegoAdapter,
    JSONSchemaAdapter,
    SemanticVectorAdapter
)

class ThreatCompilationOrchestrator:
    """
    Core orchestrator engine that maps incoming threat feed records to the IR schema,
    runs compilation adapters concurrently, and packages the outputs into an atomic manifest.
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers

    def _compile_single_threat(self, payload: IRPayload) -> Dict[str, Any]:
        """
        Compiles all adapter targets for a single IR payload.
        """
        # Run adapters
        regex_out = RegexWAFAdapter.compile(payload)
        rego_out = OPARegoAdapter.compile(payload)
        schema_out = JSONSchemaAdapter.compile(payload)
        
        vector_out = None
        try:
            vector_out = SemanticVectorAdapter.compile(payload)
        except ValueError:
            # Handle cases where centroids aren't provided by the feed (optional validation check)
            pass

        return {
            "threat_id": payload.threat_id,
            "category": payload.category,
            "regex": regex_out,
            "rego": rego_out,
            "json_schema": schema_out,
            "vector_payload": vector_out
        }

    def compile_batch(self, raw_feed: List[Dict[str, Any]], version: str = None) -> Dict[str, Any]:
        """
        Ingests raw feed list, normalizes, maps to IR schema, compiles concurrently,
        and generates the egress JSON manifest with cryptographic checksum.
        """
        if not version:
            version = f"v_{int(time.time())}"

        ir_payloads: List[IRPayload] = []
        for idx, record in enumerate(raw_feed):
            threat_id = record.get("threat_id") or f"THREAT_{idx}_{int(time.time())}"
            category = record.get("category") or "general_jailbreak"
            raw_text = record.get("text") or ""
            
            # Run normalization pipeline
            canonical_text = ThreatNormalizer.normalize_text(raw_text)
            tokens = ThreatNormalizer.tokenize(raw_text)
            
            # Extract centroids and constraints
            centroids = record.get("centroids") or []
            constraints = record.get("constraints") or {}
            metadata = record.get("metadata") or {}

            # Map through intermediate representation schema
            ir_payload = IRPayload(
                threat_id=threat_id,
                category=category,
                canonical_text=canonical_text,
                tokens=tokens,
                centroids=centroids,
                constraints=constraints,
                metadata=metadata
            )
            ir_payloads.append(ir_payload)

        compiled_signatures: Dict[str, Any] = {}

        # Compile payloads concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_payload = {
                executor.submit(self._compile_single_threat, p): p for p in ir_payloads
            }
            for future in as_completed(future_to_payload):
                payload_ref = future_to_payload[future]
                try:
                    result = future.result()
                    compiled_signatures[payload_ref.threat_id] = {
                        "category": result["category"],
                        "regex": result["regex"],
                        "rego": result["rego"],
                        "json_schema": result["json_schema"],
                        "vector_payload": result["vector_payload"]
                    }
                except Exception as exc:
                    # Robust error handling for isolated compilation failures
                    compiled_signatures[payload_ref.threat_id] = {
                        "category": payload_ref.category,
                        "error": f"Compilation failed: {str(exc)}"
                    }

        # Calculate manifest metadata and checksum
        signatures_str = json.dumps(compiled_signatures, sort_keys=True)
        sha256_checksum = hashlib.sha256(signatures_str.encode("utf-8")).hexdigest()

        manifest = {
            "manifest_version": version,
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "threat_count": len(ir_payloads),
            "signatures": compiled_signatures,
            "sha256_checksum": sha256_checksum
        }
        return manifest

    def compile_and_package(self, raw_feed: List[Dict[str, Any]], output_path: str, version: str = None) -> None:
        """
        Compiles the batch feed and writes the atomic manifest JSON file.
        """
        manifest = self.compile_batch(raw_feed, version=version)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
