import os
import logging
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from threat_transpiler.orchestrator import ThreatCompilationOrchestrator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threat_transpiler_api")

app = FastAPI(title="Threat Transpiler API", version="1.0.0")

# Enable CORS for local cross-container calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = ThreatCompilationOrchestrator(max_workers=4)

@app.post("/transpile")
def transpile_threat_feed(feed: List[Dict[str, Any]]):
    """
    Accepts a list of raw threat objects, compiles them into normalized IR payloads,
    runs the multi-target adapters, and returns the versioned, checksummed JSON manifest.
    """
    logger.info(f"Received transpile request for {len(feed)} threat feed items.")
    try:
        manifest = orchestrator.compile_batch(feed)
        logger.info("Transpilation compiled successfully.")
        return manifest
    except Exception as e:
        logger.exception("Failed to compile threat feed batch:")
        raise HTTPException(status_code=500, detail=f"Transpilation compilation failed: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "HEALTHY"}
