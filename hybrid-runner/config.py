import os
import uuid
import logging

logger = logging.getLogger("g1163rt_agent.config")

SAAS_URL = os.environ.get("SAAS_URL", "http://localhost:3001").rstrip("/")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))

# Persistent runner ID helper
RUNNER_ID_FILE = ".runner_id"
if os.path.exists(RUNNER_ID_FILE):
    try:
        with open(RUNNER_ID_FILE, "r") as f:
            RUNNER_ID = f.read().strip()
    except Exception as e:
        logger.warning(f"Failed to read local runner ID file: {e}. Generating new key.")
        RUNNER_ID = str(uuid.uuid4())[:8]
else:
    RUNNER_ID = str(uuid.uuid4())[:8]
    try:
        with open(RUNNER_ID_FILE, "w") as f:
            f.write(RUNNER_ID)
    except Exception as e:
        logger.warning(f"Could not persist runner ID to disk: {e}")

INTEL_API_KEY = os.environ.get("INTEL_API_KEY", "ent_key_secops_wallstreet_9921")
INTEL_METADATA_FILE = "intel_metadata.json"

import os
import sys
import json
import hashlib
from datetime import datetime, timedelta

def verify_onprem_license():
    license_path = "license.json"
    if not os.path.exists(license_path):
        sys.stderr.write("=======================================================\n")
        sys.stderr.write("CRITICAL LICENSE ERROR: license.json file is missing.\n")
        sys.stderr.write("Please run the installer from an extracted trial bundle.\n")
        sys.stderr.write("=======================================================\n")
        sys.exit(1)
        
    try:
        with open(license_path, "r") as f:
            data = json.load(f)
            
        activation_str = data.get("activation_date")
        duration_days = data.get("duration_days", 30)
        signature = data.get("signature")
        
        secret = "g1163rt_onprem_license_key_2026"
        sig_source = f"{activation_str}:{duration_days}:{secret}"
        expected_sig = hashlib.sha256(sig_source.encode()).hexdigest()
        
        if signature != expected_sig:
            sys.stderr.write("=======================================================\n")
            sys.stderr.write("CRITICAL LICENSE ERROR: Invalid license signature.\n")
            sys.stderr.write("Tampering detected. Terminating execution.\n")
            sys.stderr.write("=======================================================\n")
            sys.exit(1)
            
        activation_date = datetime.fromisoformat(activation_str.replace("Z", "+00:00"))
        if activation_date.tzinfo is not None:
            now = datetime.now(activation_date.tzinfo)
        else:
            now = datetime.now()
            
        expiry_date = activation_date + timedelta(days=duration_days)
        if now > expiry_date:
            sys.stderr.write("=======================================================\n")
            sys.stderr.write("CRITICAL LICENSE ERROR: The G1163RT Trial License has EXPIRED.\n")
            sys.stderr.write(f"This trial package expired on {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}.\n")
            sys.stderr.write("Please upgrade at https://g1163rt.ai/\n")
            sys.stderr.write("=======================================================\n")
            sys.exit(1)
            
    except Exception as e:
        sys.stderr.write(f"CRITICAL LICENSE ERROR: Failed to verify license: {e}\n")
        sys.exit(1)

verify_onprem_license()


