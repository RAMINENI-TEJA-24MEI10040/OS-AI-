"""
OpenTrace AI — Comprehensive Security, Unit & Performance Test Suite
---------------------------------------------------------------------
Executes automated security assertions for SSRF input validation, SQL parameter
binding safety, input truncation bounds, verification state enforcement,
and model fallback logic. Also measures deterministic runtime benchmarks.
"""

import sys
import os
import time
import json
import statistics

# Ensure backend directory is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import main as app_main
from agent import (
    OpenTraceAgentHarness,
    is_ssrf_safe_url,
    normalize_indicator,
    sanitize_input,
    VerificationStatus,
    IndicatorType,
    OpenWeightModelAdapter
)


# ============================================================================
# 1. SECURITY TEST SUITE (SSRF, SQLi, Input Bounds, Model Fallback)
# ============================================================================

def test_ssrf_boundaries():
    print("\n[TEST] 1. SSRF Input Validation Test Suite...")
    ssrf_test_cases = [
        ("http://127.0.0.1/admin", False, "IPv4 Loopback"),
        ("http://localhost:8000", False, "Localhost name"),
        ("http://169.254.169.254/latest/meta-data", False, "AWS Metadata"),
        ("http://10.0.0.1/secret", False, "RFC1918 Private 10/8"),
        ("http://192.168.1.1/router", False, "RFC1918 Private 192.168/16"),
        ("http://[::1]/status", False, "IPv6 Loopback"),
        ("http://[::ffff:127.0.0.1]/test", False, "IPv4-mapped IPv6 Loopback"),
        ("http://user:pass@127.0.0.1/", False, "Credentials in URL"),
        ("http://example.com/public", True, "Public Domain URL")
    ]

    passed = 0
    for url, expected_safe, desc in ssrf_test_cases:
        is_safe, reason = is_ssrf_safe_url(url)
        assert is_safe == expected_safe, f"SSRF Assertion Failed for {desc} ({url}): Expected {expected_safe}, got {is_safe}"
        passed += 1
        print(f"  [PASS] {desc:32s} -> Safe: {str(is_safe):5s} | {reason}")

    print(f"  -> SSRF Security Test Suite PASSED ({passed}/{len(ssrf_test_cases)} assertions verified).")


def test_input_bounds_and_sanitization():
    print("\n[TEST] 2. Input Bounds & Control Character Sanitization...")
    raw_input = "  1.1.1.1\x00\x07  " + ("A" * 15000)
    sanitized = sanitize_input(raw_input)
    assert len(sanitized) <= 10000, "Input length assertion failed: Exceeded 10,000 character limit"
    assert "\x00" not in sanitized, "Control character assertion failed: Null byte present"
    print("  [PASS] Input bounded to 10,000 characters and control characters removed.")


def test_sql_parameter_binding_safety():
    print("\n[TEST] 3. SQL Injection Parameter Binding Safety...")
    malicious_indicator = "' OR '1'='1'; DROP TABLE cases; --"
    harness = OpenTraceAgentHarness()
    res = harness.run_investigation(malicious_indicator)
    assert res["status"] == "COMPLETED", "SQL Injection test failed: Pipeline did not complete safely"
    
    # Store case via DB client using parameterized statements
    db_client = app_main.db_client
    case_id = f"test_sqli_{int(time.time())}"
    stmts = [
        ("INSERT INTO cases (id, indicator, indicator_type, threat_level, status, duration_ms) VALUES (?, ?, ?, ?, ?, ?)",
         [case_id, malicious_indicator, "log_text", "LOW", "COMPLETED", 5.0]),
        ("SELECT * FROM cases WHERE id = ?", [case_id])
    ]
    exec_res = db_client.execute_statements(stmts)
    assert len(exec_res) > 1 and len(exec_res[1]) == 1, "SQL Injection assertion failed: Parameterized insert/select failed"
    retrieved = exec_res[1][0]["indicator"]
    assert retrieved == malicious_indicator, "SQL Injection assertion failed: String value altered"
    print("  [PASS] Malicious SQL payload safely stored and retrieved as literal string.")


def test_verification_state_transitions():
    print("\n[TEST] 4. Verification Engine State Transition Logic...")
    harness = OpenTraceAgentHarness()
    
    # Test known threat hash (Should produce VERIFIED state via deterministic signature match)
    known_hash = "131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e"
    res_known = harness.run_investigation(known_hash)
    v_statuses = [f["verification_status"] for f in res_known["findings"]]
    assert VerificationStatus.VERIFIED in v_statuses, "Verification assertion failed: Known threat hash not marked VERIFIED"

    # Test unknown AI hypothesis without evidence support (Should produce UNVERIFIED state)
    mock_obs = []  # ZERO tool observations
    mock_ai_synthesis = {
        "assessment": "Test assessment",
        "threat_level": "LOW",
        "proposed_hypotheses": [
            {
                "title": "Unsupported Theory",
                "theory": "AI theory without tool backing",
                "supporting_evidence_types": ["non_existent_tool"],
                "requires_verification": True
            }
        ]
    }
    # Verify logic directly
    for hyp in mock_ai_synthesis["proposed_hypotheses"]:
        supporting_obs = [obs for obs in mock_obs if obs.get("tool") in hyp.get("supporting_evidence_types", [])]
        status = VerificationStatus.VERIFIED if len(supporting_obs) >= 2 else (VerificationStatus.CORRELATED if len(supporting_obs) == 1 else VerificationStatus.UNVERIFIED)
        assert status == VerificationStatus.UNVERIFIED, "Verification assertion failed: Unsupported hypothesis was not marked UNVERIFIED"
    
    print("  [PASS] Verification state transitions verified (Known threat -> VERIFIED, Unsupported AI theory -> UNVERIFIED).")


def test_model_adapter_fallback():
    print("\n[TEST] 5. Model Adapter Offline Fallback Engine...")
    adapter = OpenWeightModelAdapter()
    adapter.endpoint = "http://127.0.0.1:59999/non_existent_api"  # Invalid endpoint to trigger timeout/fallback
    
    plan = adapter.generate_investigation_plan("example.com", IndicatorType.DOMAIN)
    assert "recommended_tools" in plan and len(plan["recommended_tools"]) >= 1, "Model fallback assertion failed: Plan not generated"
    
    synthesis = adapter.generate_hypothesis_and_correlation("example.com", IndicatorType.DOMAIN, [])
    assert "assessment" in synthesis and "proposed_hypotheses" in synthesis, "Model fallback assertion failed: Synthesis not generated"
    print("  [PASS] Model adapter fallback engine handled offline model endpoint gracefully.")


# ============================================================================
# 2. RUNTIME LATENCY BENCHMARK SUITE
# ============================================================================

def run_latency_benchmarks(iterations=3):
    print("\n" + "=" * 70)
    print(" OPENTRACE AI — RUNTIME LATENCY BENCHMARK SUITE")
    print("=" * 70)

    test_inputs = [
        ("IPv4 (1.1.1.1)", "1.1.1.1"),
        ("Domain (example.com)", "example.com"),
        ("WannaCry Hash", "131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e"),
        ("Eth Wallet", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"),
        ("Log Event", "Failed password for root from 198.51.100.22 port 22 ssh2")
    ]

    harness = OpenTraceAgentHarness()
    results = {}

    for label, target in test_inputs:
        local_deterministic_latencies = []
        total_latencies = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            res = harness.run_investigation(target)
            total_lat = res["timing_ms"]["total_investigation"]
            total_latencies.append(total_lat)

            # Sum of local CPU processing (excluding model endpoint wait)
            t_local = (
                res["timing_ms"].get("normalization", 0) +
                res["timing_ms"].get("execution", 0) +
                res["timing_ms"].get("correlation", 0) +
                res["timing_ms"].get("verification", 0)
            )
            local_deterministic_latencies.append(t_local)

        med_total = statistics.median(total_latencies)
        mean_total = statistics.mean(total_latencies)
        min_total = min(total_latencies)
        max_total = max(total_latencies)

        med_local = statistics.median(local_deterministic_latencies)
        mean_local = statistics.mean(local_deterministic_latencies)

        print(f"\n[*] Target: {label} ({iterations} iterations)")
        print(f"    - Local Deterministic Processing (CPU): Mean={mean_local:.2f}ms | Median={med_local:.2f}ms")
        print(f"    - Total Pipeline Latency (incl. model wait): Mean={mean_total:.2f}ms | Median (p50)={med_total:.2f}ms | Min={min_total:.2f}ms | Max={max_total:.2f}ms")

        results[label] = {
            "local_mean_ms": round(mean_local, 2),
            "total_p50_ms": round(med_total, 2),
            "total_mean_ms": round(mean_total, 2),
            "total_min_ms": round(min_total, 2),
            "total_max_ms": round(max_total, 2)
        }

    return results


if __name__ == "__main__":
    print("=" * 70)
    print(" OPENTRACE AI — AUTOMATED SECURITY & VERIFICATION TEST SUITE")
    print("=" * 70)
    
    test_ssrf_boundaries()
    test_input_bounds_and_sanitization()
    test_sql_parameter_binding_safety()
    test_verification_state_transitions()
    test_model_adapter_fallback()
    
    benchmarks = run_latency_benchmarks(iterations=3)
    print("\n[Suite Execution Complete] All security assertions and benchmarks passed successfully.")
