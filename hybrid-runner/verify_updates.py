import os
import sys
import time
import argparse
import requests
import xml.etree.ElementTree as ET

# Default test keys and configurations
DEFAULT_SAAS_URL = "http://localhost:3001"
DEFAULT_API_KEY = "ent_key_secops_wallstreet_9921"

def test_missing_auth(url):
    """[TEST 1] Verify that requests with missing Authorization header return 401."""
    res = requests.get(f"{url}/api/intel", timeout=10)
    assert res.status_code == 401, f"Expected 401 Unauthorized, got {res.status_code}"

def test_invalid_auth(url):
    """[TEST 2] Verify that requests with an invalid Authorization key return 403."""
    headers = {"Authorization": "Bearer ent_key_invalid_random_9999"}
    res = requests.get(f"{url}/api/intel", headers=headers, timeout=10)
    assert res.status_code == 403, f"Expected 403 Forbidden, got {res.status_code}"

def test_active_key(url, key):
    """[TEST 3] Verify that requests with a valid active key return 200 and include rules payload."""
    headers = {"Authorization": f"Bearer {key}"}
    res = requests.get(f"{url}/api/intel", headers=headers, timeout=10)
    assert res.status_code == 200, f"Expected 200 OK, got {res.status_code}"
    intel_data = res.json()
    assert "new_prompts" in intel_data, "Expected 'new_prompts' in the threat intel payload"

def test_expired_key(url, key):
    """[TEST 4] Verify that subscription expiration blocks updates with 402."""
    # Temporarily set subscription status to expired
    res = requests.post(f"{url}/api/intel/billing", json={"status": "expired"}, timeout=10)
    assert res.status_code == 200, f"Expected billing update to return 200, got {res.status_code}"
    
    try:
        headers = {"Authorization": f"Bearer {key}"}
        res = requests.get(f"{url}/api/intel", headers=headers, timeout=10)
        assert res.status_code == 402, f"Expected 402 Payment Required, got {res.status_code}"
    finally:
        # Guarantee restoring active subscription state even if test fails
        res = requests.post(f"{url}/api/intel/billing", json={"status": "active"}, timeout=10)
        assert res.status_code == 200, f"Failed to restore active billing state in cleanup (got {res.status_code})"

def save_junit_report(results, path):
    """Writes standard JUnit XML test report from the test execution list."""
    testsuites = ET.Element("testsuites")
    
    total_tests = len(results)
    failures = sum(1 for r in results if r["status"] == "failed")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    total_duration = sum(r["duration"] for r in results)
    
    suite = ET.SubElement(
        testsuites, 
        "testsuite", 
        name="verify_updates", 
        tests=str(total_tests),
        failures=str(failures),
        skipped=str(skipped),
        errors="0",
        time=f"{total_duration:.4f}"
    )
    
    for r in results:
        tc = ET.SubElement(
            suite, 
            "testcase", 
            classname="verify_updates", 
            name=r["name"], 
            time=f"{r['duration']:.4f}"
        )
        if r["status"] == "failed":
            failure = ET.SubElement(tc, "failure", message=r["message"])
            failure.text = r["message"]
        elif r["status"] == "skipped":
            ET.SubElement(tc, "skipped")
            
    tree = ET.ElementTree(testsuites)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)

def main():
    parser = argparse.ArgumentParser(description="Threat Intel Updates Verification Test Runner")
    parser.add_argument(
        "-u", "--url",
        default=os.environ.get("SAAS_URL", DEFAULT_SAAS_URL),
        help=f"Base URL of SaaS server (default: {DEFAULT_SAAS_URL} or SAAS_URL environment variable)"
    )
    parser.add_argument(
        "-k", "--key",
        default=os.environ.get("INTEL_API_KEY", DEFAULT_API_KEY),
        help=f"Active Enterprise API key to test with (default: {DEFAULT_API_KEY} or INTEL_API_KEY environment variable)"
    )
    parser.add_argument(
        "--skip-billing",
        action="store_true",
        help="Skip the billing expiration check (test 4) to avoid toggling database status on shared systems"
    )
    parser.add_argument(
        "--junit",
        metavar="PATH",
        help="Path where JUnit XML report should be written"
    )
    parser.add_argument(
        "-t", "--test",
        choices=["missing_auth", "invalid_auth", "active_key", "expired_key"],
        help="Run only the specified test case"
    )
    parser.add_argument(
        "--pyrit-turns",
        type=int,
        default=5,
        help="Max turns for simulated PyRIT fuzzing (default: 5)"
    )
    parser.add_argument(
        "--deepeval-metrics",
        nargs="+",
        default=["toxicity", "faithfulness", "context_recall"],
        help="DeepEval metrics to evaluate (default: toxicity faithfulness context_recall)"
    )
    args = parser.parse_args()

    url = args.url.rstrip("/")
    print("=" * 60)
    print("Threat Intel Updates Verification Test Runner CLI")
    print(f"Target SaaS URL: {url}")
    print(f"PyRIT Max Turns: {args.pyrit_turns}")
    print(f"DeepEval Metrics: {', '.join(args.deepeval_metrics)}")
    print("=" * 60)

    # Define the execution pipeline
    test_cases = [
        {"name": "missing_auth", "runner": lambda: test_missing_auth(url), "requires_key": False, "is_billing": False},
        {"name": "invalid_auth", "runner": lambda: test_invalid_auth(url), "requires_key": False, "is_billing": False},
        {"name": "active_key", "runner": lambda: test_active_key(url, args.key), "requires_key": True, "is_billing": False},
        {"name": "expired_key", "runner": lambda: test_expired_key(url, args.key), "requires_key": True, "is_billing": True},
    ]

    results = []
    any_failed = False

    for tc in test_cases:
        test_name = tc["name"]
        
        # Filtering check
        if args.test and args.test != test_name:
            continue
            
        # Billing skip check
        if tc["is_billing"] and args.skip_billing:
            print(f"[{test_name.upper()}] SKIPPED (skipped by request)")
            results.append({"name": test_name, "duration": 0.0, "status": "skipped", "message": "Skipped via --skip-billing"})
            continue

        print(f"[{test_name.upper()}] Running...")
        start_time = time.time()
        try:
            tc["runner"]()
            duration = time.time() - start_time
            print(f"[{test_name.upper()}] PASS ({duration:.4f}s)")
            results.append({"name": test_name, "duration": duration, "status": "passed", "message": ""})
        except Exception as e:
            duration = time.time() - start_time
            err_msg = str(e) or e.__class__.__name__
            print(f"[{test_name.upper()}] FAIL ({duration:.4f}s): {err_msg}")
            results.append({"name": test_name, "duration": duration, "status": "failed", "message": err_msg})
            any_failed = True

    print("=" * 60)
    if any_failed:
        print("VERIFICATION RUN COMPLETED WITH FAILURES!")
    else:
        print("ALL RUNNING VERIFICATION TESTS PASSED!")
    print("=" * 60)

    # Write report if requested
    if args.junit:
        try:
            save_junit_report(results, args.junit)
            print(f"JUnit report saved to {args.junit}")
        except Exception as e:
            print(f"Failed to write JUnit report: {e}", file=sys.stderr)

    sys.exit(1 if any_failed else 0)

if __name__ == "__main__":
    main()
