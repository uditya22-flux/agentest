"""
AgentBridge v5 — Stress Test
Tests all endpoints under load and validates Groq AI responses.

Usage:
    python stress_test.py --backend https://your-app.onrender.com --api_key demo_key_001
    python stress_test.py --backend http://localhost:8000 --api_key test123 --requests 50
"""
import httpx
import time
import json
import uuid
import argparse
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("--backend", default="http://localhost:8000")
parser.add_argument("--api_key", default="demo_key_001")
parser.add_argument("--requests", type=int, default=20)
parser.add_argument("--concurrency", type=int, default=5)
args = parser.parse_args()

BASE = args.backend.rstrip("/")
KEY = args.api_key
RESULTS = []

# ── Test scenarios ──────────────────────────────────────────────

SCENARIOS = [
    {
        "name": "Clean approval with KYC",
        "expect_verdict": "allow",
        "payload": {
            "api_key": KEY,
            "agent_id": "FraudDetector-v2",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_001",
            "action_type": "approve",
            "input": {"amount": 15000, "kyc_verified": True, "risk_score": 0.2},
            "output": {"approved": True},
            "reasoning": "Customer has verified KYC and clean transaction history. Risk score within acceptable threshold.",
            "confidence": 0.92,
        }
    },
    {
        "name": "High value no KYC — should REJECT",
        "expect_verdict": "reject",
        "payload": {
            "api_key": KEY,
            "agent_id": "PaymentAgent-v1",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_002",
            "action_type": "approve",
            "input": {"amount": 75000, "kyc_verified": False},
            "output": {"approved": True},
            "reasoning": "Automated approval based on transaction history.",
            "confidence": 0.88,
        }
    },
    {
        "name": "Critical confidence — should REJECT",
        "expect_verdict": "reject",
        "payload": {
            "api_key": KEY,
            "agent_id": "CreditAgent-v3",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_003",
            "action_type": "approve",
            "input": {"amount": 30000, "kyc_verified": True},
            "output": {"approved": True},
            "reasoning": "Model confidence is low but approving anyway.",
            "confidence": 0.45,
        }
    },
    {
        "name": "PEP detection — should REVIEW",
        "expect_verdict": "review",
        "payload": {
            "api_key": KEY,
            "agent_id": "KYCAgent-v1",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_004",
            "action_type": "approve",
            "input": {"amount": 10000, "kyc_verified": True, "is_pep": True, "risk_score": 0.4},
            "output": {"approved": True},
            "reasoning": "KYC verified. Customer flagged as politically exposed person.",
            "confidence": 0.82,
        }
    },
    {
        "name": "Fraud flag action",
        "expect_verdict": "allow",
        "payload": {
            "api_key": KEY,
            "agent_id": "FraudDetector-v2",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_005",
            "action_type": "flag",
            "input": {"transaction_id": "TXN_9999", "suspicious_pattern": "velocity_spike"},
            "output": {"flagged": True, "reason": "3 transactions in 90 seconds"},
            "reasoning": "Transaction velocity exceeds normal pattern. Flagging for review.",
            "confidence": 0.91,
        }
    },
    {
        "name": "Critical value requires EDD — should REJECT",
        "expect_verdict": "reject",
        "payload": {
            "api_key": KEY,
            "agent_id": "LoanAgent-v1",
            "session_id": f"stress-{uuid.uuid4().hex[:8]}",
            "user_id": "user_006",
            "action_type": "approve",
            "input": {"amount": 250000, "kyc_verified": True},
            "output": {"approved": True},
            "reasoning": "Large loan approved based on credit score.",
            "confidence": 0.78,
        }
    },
    {
        "name": "Manual UI log submission",
        "endpoint": "/log-manual",
        "expect_verdict": None,
        "payload": {
            "api_key": KEY,
            "agent_name": "UITestAgent",
            "action_type": "query",
            "input": {"customer_id": "CUST_UI_001", "query_type": "balance_check"},
            "output": {"balance": 45000},
            "reasoning": "Routine balance inquiry submitted via UI.",
        }
    },
]


def send_request(scenario, idx):
    endpoint = scenario.get("endpoint", "/decide")
    url = f"{BASE}{endpoint}"
    start = time.time()
    try:
        r = httpx.post(url, json=scenario["payload"], timeout=30)
        elapsed = round((time.time() - start) * 1000)
        data = r.json()
        verdict = data.get("verdict", "—")
        expected = scenario.get("expect_verdict")
        passed = (expected is None) or (verdict == expected)
        ai_explanation = data.get("ai_explanation", "")[:80] if data.get("ai_explanation") else "—"
        return {
            "idx": idx,
            "scenario": scenario["name"],
            "status": r.status_code,
            "verdict": verdict,
            "expected": expected or "any",
            "passed": passed,
            "latency_ms": elapsed,
            "ai_enabled": bool(ai_explanation and ai_explanation != "—"),
            "ai_snippet": ai_explanation,
            "risk_score": data.get("risk_score", "—"),
            "error": None,
        }
    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        return {
            "idx": idx,
            "scenario": scenario["name"],
            "status": 0,
            "verdict": "ERROR",
            "expected": scenario.get("expect_verdict", "any"),
            "passed": False,
            "latency_ms": elapsed,
            "ai_enabled": False,
            "ai_snippet": "—",
            "risk_score": "—",
            "error": str(e),
        }


def run_stress():
    print(f"\n{'='*70}")
    print(f"  AgentBridge v5 — Stress Test")
    print(f"  Backend : {BASE}")
    print(f"  API Key : {KEY}")
    print(f"  Requests: {args.requests}  Concurrency: {args.concurrency}")
    print(f"{'='*70}\n")

    # Health check first
    try:
        h = httpx.get(f"{BASE}/health", timeout=10)
        health = h.json()
        print(f"  Health: {health.get('status')} | AI: {health.get('ai_analysis')}\n")
    except Exception as e:
        print(f"  WARNING: Health check failed: {e}\n")

    # Build request list
    jobs = []
    for i in range(args.requests):
        scenario = SCENARIOS[i % len(SCENARIOS)]
        # Give each job unique session_id
        s = dict(scenario)
        s["payload"] = dict(scenario["payload"])
        s["payload"]["session_id"] = f"stress-{uuid.uuid4().hex[:8]}"
        jobs.append((s, i + 1))

    # Run concurrently
    start_all = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(send_request, s, i) for s, i in jobs]
        for f in as_completed(futures):
            r = f.result()
            RESULTS.append(r)
            status_icon = "✓" if r["passed"] else "✗"
            ai_icon = "🤖" if r["ai_enabled"] else "  "
            print(f"  {status_icon} {ai_icon} [{r['idx']:>3}] {r['scenario'][:40]:<40} "
                  f"verdict={r['verdict']:<8} expected={r['expected']:<8} "
                  f"{r['latency_ms']}ms")
            if r["error"]:
                print(f"       ERROR: {r['error']}")

    total_time = round((time.time() - start_all) * 1000)

    # Summary
    passed = sum(1 for r in RESULTS if r["passed"])
    failed = len(RESULTS) - passed
    ai_responses = sum(1 for r in RESULTS if r["ai_enabled"])
    latencies = [r["latency_ms"] for r in RESULTS]
    avg_lat = round(sum(latencies) / len(latencies)) if latencies else 0
    p95 = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0
    errors = [r for r in RESULTS if r["error"]]

    print(f"\n{'='*70}")
    print(f"  RESULTS")
    print(f"{'='*70}")
    print(f"  Total requests  : {len(RESULTS)}")
    print(f"  Passed          : {passed} ({round(passed/len(RESULTS)*100)}%)")
    print(f"  Failed          : {failed}")
    print(f"  AI responses    : {ai_responses}/{len(RESULTS)} (Groq active: {ai_responses > 0})")
    print(f"  Avg latency     : {avg_lat}ms")
    print(f"  P95 latency     : {p95}ms")
    print(f"  Total wall time : {total_time}ms")
    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for e in errors[:5]:
            print(f"    [{e['idx']}] {e['scenario']}: {e['error']}")
    print(f"{'='*70}\n")

    # Verdict breakdown
    from collections import Counter
    verdicts = Counter(r["verdict"] for r in RESULTS)
    print("  Verdict breakdown:")
    for v, count in verdicts.most_common():
        print(f"    {v:<12} {count}")
    print()

    # Save results
    out = f"stress_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"  Results saved to: {out}\n")

    return failed == 0


if __name__ == "__main__":
    ok = run_stress()
    exit(0 if ok else 1)
