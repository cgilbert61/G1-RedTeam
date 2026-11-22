import logging
from typing import List, Dict, Any, Optional, Union
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from threat_transpiler.orchestrator import ThreatCompilationOrchestrator
from threat_transpiler.compliance_matrix import get_frameworks_catalog
from threat_transpiler.mutators import list_mutators

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threat_transpiler_api")

app = FastAPI(title="Threat Transpiler API", version="1.1.0")

# Enable CORS for local cross-container calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = ThreatCompilationOrchestrator(max_workers=4)


class TranspileRequest(BaseModel):
    """Structured transpile request supporting optional mutators and deterministic seed."""

    feed: List[Dict[str, Any]] = Field(..., description="Raw threat feed items to compile.")
    mutators: List[str] = Field(
        default_factory=list,
        description="Optional adversarial mutator names to expand each threat item.",
    )
    seed: Optional[int] = Field(
        default=None,
        description="Optional deterministic PRNG seed for reproducible mutations.",
    )
    version: Optional[str] = Field(default=None, description="Optional manifest version tag.")


@app.post("/transpile")
def transpile_threat_feed(
    payload: Union[List[Dict[str, Any]], TranspileRequest],
    mutators: Optional[List[str]] = Query(default=None),
    seed: Optional[int] = Query(default=None),
):
    """
    Accepts either a list of raw threat objects (with optional ?mutators=&seed= query params)
    or a TranspileRequest object {feed, mutators, seed}, expands variants if mutators are
    requested, compiles into normalized IR + multi-target adapters + engine manifests, and
    returns the versioned, checksummed JSON manifest.
    """
    if isinstance(payload, TranspileRequest):
        feed = payload.feed
        active_mutators = payload.mutators or (mutators or [])
        active_seed = payload.seed if payload.seed is not None else seed
        version = payload.version
    else:
        feed = payload
        active_mutators = mutators or []
        active_seed = seed
        version = None

    logger.info(
        f"Received transpile request for {len(feed)} threat feed items "
        f"(mutators={active_mutators}, seed={active_seed})."
    )
    try:
        manifest = orchestrator.compile_batch(
            feed,
            version=version,
            mutators=active_mutators,
            seed=active_seed,
        )
        logger.info("Transpilation compiled successfully.")
        return manifest
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.exception("Failed to compile threat feed batch:")
        raise HTTPException(
            status_code=500,
            detail=f"Transpilation compilation failed: {str(e)}",
        )


@app.get("/compliance/frameworks")
def list_compliance_frameworks():
    """Return the canonical vulnerability taxonomy and 8-framework compliance matrix."""
    return get_frameworks_catalog()


@app.get("/mutators")
def get_available_mutators():
    """Return the list of supported deterministic payload mutators."""
    return {"mutators": list_mutators()}


@app.get("/health")
def health_check():
    return {"status": "HEALTHY"}
