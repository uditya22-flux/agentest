"""
AgentBridge v5 Demo Agent
Demonstrates the decision gateway — agent CANNOT execute without gateway approval.

Usage:
    python demo_agent.py --api_key test123 --backend https://agentbridge-test.onrender.com
"""
import httpx
import argparse
import uuid
import time

parser = argparse.ArgumentParser()
parser.add_argument("--api_key", default="test123")
parser.add_argument("--backend", default="https://agentbridge-test.onrender.com")
args = parser.parse_args()

HEADERS = {"X-API-Key": args.api_key, "Content-Type": "application/json"}
SESSION_ID = str(uuid.uuid4())

def decide(action_type, input_data, reasoning, confidence, label):
    payload = {
        "session_id": SESSION_ID,
        "agent_id": "demo-fraud-agent",
        "user_id": f"user_{uuid.uuid4().hex[:8]}",
        "action_type": action_type,
        "input": input_data,
        "reasoning": reasoning,
        "confidence": confidence,
        "domain": "fintech",
    }
    r = httpx.post(f"{args.backend}/decide", json=payload, headers=HEADERS, timeout=15)
    data = r.json()
    verdict = data.get("verdict", "unknown").upper()
    print(f"\n  {label}")
    print(f"  → Verdict: {verdict} (HTTP {r.status_code})")
    print(f"  → Risk score: {data.get('risk_score', 'N/A')}")
    if data.get("ai_explanation"):
        print(f"  → AI: {data['ai_explanation'][:120]}...")
    if data.get("policy_violations"):
        print(f"  → Policy: {data['policy_violations'][0][:100]}")
    return data

print(f"\n🔐 AgentBridge v5 Decision Gateway Demo")
print(f"   API Key: {args.api_key}")
print(f"   Backend: {args.backend}")
print(f"   Session: {SESSION_ID}\n")

# Scenario 1 — BLOCKED: no KYC
decide("approve", {"amount": 75000, "kyc_verified": False},
       "High value transfer requested", 0.85,
       "❌ Scenario 1: High value, no KYC — expect REJECT")
time.sleep(0.5)

# Scenario 2 — BLOCKED: no reasoning (will fail validation)
try:
    decide("approve", {"amount": 10000, "kyc_verified": True},
           "", 0.90, "❌ Scenario 2: Empty reasoning — expect 422")
except Exception as e:
    print(f"  → Blocked at validation: {e}")
time.sleep(0.5)

# Scenario 3 — REVIEW: high value, low confidence
decide("approve", {"amount": 80000, "kyc_verified": True},
       "Transfer within daily limit, customer verified", 0.65,
       "⚠️  Scenario 3: High value + low confidence — expect REVIEW")
time.sleep(0.5)

# Scenario 4 — ALLOW: clean transaction
decide("approve", {"amount": 5000, "kyc_verified": True, "risk_score": 0.1},
       "Low value transfer, KYC verified, risk score within threshold", 0.95,
       "✅ Scenario 4: Clean transaction — expect ALLOW")
time.sleep(0.5)

# Scenario 5 — REVIEW: PEP detected
decide("approve", {"amount": 20000, "kyc_verified": True, "is_pep": True},
       "Transfer for PEP customer, standard verification completed", 0.85,
       "⚠️  Scenario 5: PEP detected — expect REVIEW")

print("\n✅ Demo complete. Check your dashboard for audit trail.\n")
