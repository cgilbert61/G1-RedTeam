import os
import json
import time
import uuid
import requests
import logging
import threading
from .local_scanner import LocalScanner

logger = logging.getLogger("g1163rt_sdk")

class ScanResult:
    def __init__(self, is_safe, violations):
        self.is_safe = is_safe
        self.violations = violations

    def __repr__(self):
        return f"ScanResult(is_safe={self.is_safe}, violations={len(self.violations)})"

class FuzzJob:
    def __init__(self, job_id, evaluator):
        self.job_id = job_id
        self.evaluator = evaluator

    def get_status(self):
        """Fetches the current status and report of the job from the dashboard."""
        url = f"{self.evaluator.dashboard_url}/api/jobs"
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                jobs = res.json().get("jobs", [])
                for job in jobs:
                    if job.get("id") == self.job_id:
                        return {
                            "status": job.get("status", "pending"),
                            "report": job.get("report")
                        }
            return {"status": "error", "error": f"Failed status fetch: {res.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def wait_for_completion(self, timeout_seconds=60, poll_interval=2):
        """Polls until the job status becomes 'completed', 'failed', or times out."""
        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            status_info = self.get_status()
            status = status_info.get("status")
            if status in ("completed", "failed"):
                # Return standard success based on vulnerabilities found in the report
                report = status_info.get("report") or {}
                stats = report.get("stats") or {}
                vulns = stats.get("vulnerabilities_detected", 0)
                return {
                    "success": vulns == 0,
                    "status": status,
                    "vulnerabilities": vulns,
                    "report": report
                }
            time.sleep(poll_interval)
        return {
            "success": False,
            "status": "timeout",
            "error": f"Job execution timed out after {timeout_seconds} seconds"
        }

class RedTeamEvaluator:
    def __init__(self, api_key=None, dashboard_url=None, cache_file=None):
        self.api_key = api_key or os.environ.get("G1163RT_API_KEY")
        self.dashboard_url = (dashboard_url or 
                              os.environ.get("G1163RT_DASHBOARD_URL", "http://localhost:3000")).rstrip("/")
        
        # Default local cache file in the current working directory or user home
        if not cache_file:
            home = os.path.expanduser("~")
            self.cache_file = os.path.join(home, ".g1163rt_intel_cache.json")
        else:
            self.cache_file = cache_file

        self.threat_signatures = []
        self._initialize_signatures()

    def _initialize_signatures(self):
        # 1. Try to fetch fresh telemetry from Dashboard
        fetched = False
        if self.api_key:
            try:
                fetched = self.fetch_latest_intel()
            except Exception as e:
                logger.warning(f"Unable to fetch latest intelligence from dashboard: {e}")

        # 2. If fetch failed or no API key, load from local cache
        if not fetched:
            if os.path.exists(self.cache_file) and os.path.getsize(self.cache_file) > 0:
                try:
                    with open(self.cache_file, "r", encoding="utf-8") as f:
                        self.threat_signatures = json.load(f)
                    logger.info("Loaded threat signatures from local cache.")
                except Exception as e:
                    logger.error(f"Failed to read local threat cache: {e}")
            else:
                logger.info("No local cache file found or cache is empty. Initializing with default signature set.")

        # 3. Instantiate the local heuristic engine
        self.local_scanner = LocalScanner(self.threat_signatures)

    def fetch_latest_intel(self):
        """Fetches new prompts/signatures from the control plane and saves to cache."""
        url = f"{self.dashboard_url}/api/intel"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                package = res.json()
                new_prompts = package.get("new_prompts", {})
                
                # Transform prompts into flat keyword threat signatures
                signatures = []
                for category, prompt_list in new_prompts.items():
                    for prompt in prompt_list:
                        signatures.append({
                            "type": "keyword",
                            "pattern": prompt,
                            "category": category
                        })
                
                self.threat_signatures = signatures
                
                # Write to cache file
                with open(self.cache_file, "w", encoding="utf-8") as f:
                    json.dump(signatures, f, indent=2)
                
                logger.info("Successfully synchronized fresh threat intelligence.")
                return True
            else:
                logger.warning(f"Intel sync endpoint returned code {res.status_code}: {res.text}")
                return False
        except Exception as e:
            logger.warning(f"Network error during intel sync: {e}")
            return False

    def scan_interaction(self, prompt, response=None, target_name="CI/CD Pipeline Scan"):
        """
        Executes a low-latency check on a prompt & response.
        Fires a telemetry logging request in the background.
        """
        violations = self.local_scanner.scan(prompt, response)
        is_safe = len(violations) == 0
        
        # Fire non-blocking background thread to log telemetry back to dashboard
        if self.api_key:
            threading.Thread(
                target=self._post_telemetry,
                args=(prompt, response, violations, target_name),
                daemon=True
            ).start()

        return ScanResult(is_safe, violations)

    def _post_telemetry(self, prompt, response, violations, target_name):
        """Transmits the test logs to the central dashboard for SIEM auditing."""
        job_id = f"sdk-{uuid.uuid4().hex[:8]}"
        
        stats = {
            "total_cases": 1,
            "passed_cases": 1 if not violations else 0,
            "failed_cases": 1 if violations else 0,
            "vulnerabilities_detected": len(violations)
        }
        
        logs = []
        for v in violations:
            logs.append({
                "timestamp": time.time(),
                "level": "warning",
                "message": f"Policy violation in {v['target']}: Matched {v['category']} with '{v['match']}'"
            })
            
        if not violations:
            logs.append({
                "timestamp": time.time(),
                "level": "info",
                "message": "Interaction passed all local guardrails."
            })

        payload = {
            "job_id": job_id,
            "runner_id": "local-sdk",
            "is_external": True,
            "target_name": target_name,
            "report": {
                "status": "completed",
                "stats": stats,
                "logs": logs
            }
        }
        
        url = f"{self.dashboard_url}/api/jobs/report"
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logger.warning(f"Failed to submit telemetry report: {e}")

    def trigger_daemon_fuzz(self, target_endpoint, adversarial_goal, turns=5):
        """Enqueues an asynchronous multi-turn fuzzing job on the main runner daemon."""
        # 1. Resolve or create target
        target_id = self._resolve_target(target_endpoint)
        if not target_id:
            raise ValueError(f"Could not resolve target endpoint: {target_endpoint}")

        # 2. Trigger job with custom PyRIT configuration
        pyrit_config = {
            "attack_goal": adversarial_goal,
            "max_turns": str(turns)
        }
        
        url = f"{self.dashboard_url}/api/jobs"
        payload = {
            "targetId": target_id,
            "tests": {
                "pyrit": True
            },
            "pyrit_config": json.dumps(pyrit_config)
        }
        
        try:
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                job_data = res.json().get("job", {})
                job_id = job_data.get("id")
                if job_id:
                    logger.info(f"Triggered fuzzing job on daemon: {job_id}")
                    return FuzzJob(job_id, self)
            raise RuntimeError(f"Failed to enqueue fuzzing job: {res.text}")
        except Exception as e:
            raise RuntimeError(f"Fuzzing job trigger failed: {e}")

    def _resolve_target(self, endpoint):
        """Checks if target exists; if not, creates one and returns its ID."""
        url = f"{self.dashboard_url}/api/targets"
        try:
            # Check existing
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                targets = res.json().get("targets", [])
                for t in targets:
                    if t.get("endpoint") == endpoint:
                        return t.get("id")
            
            # Create a new target since none exists
            payload = {
                "name": f"SDK Autoresolved target",
                "endpoint": endpoint,
                "adapter_type": "openai",
                "model_name": "gpt-4o-mini",
                "headers": {},
                "request_template": '{"prompt": "$prompt"}'
            }
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                targets = res.json().get("targets", [])
                for t in targets:
                    if t.get("endpoint") == endpoint:
                        return t.get("id")
            return None
        except Exception as e:
            logger.error(f"Error resolving target endpoint: {e}")
            return None
