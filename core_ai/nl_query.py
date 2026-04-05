import os
import httpx
from typing import List, Dict, Any

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"


def query_logs(question: str, logs: List[Dict[str, Any]]) -> str:
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return "GROQ_API_KEY not set."
    if not logs:
        return "No logs found for this API key."

    total = len(logs)
    flagged = [l for l in logs if l.get("flagged")]
    high_risk = [l for l in logs if l.get("risk_level") == "high"]
    actions: Dict[str, int] = {}
    for l in logs:
        a = l.get("action_type", l.get("action", "unknown"))
        actions[a] = actions.get(a, 0) + 1

    sample = flagged[:20] if flagged else logs[:20]
    sample_clean = [
        {
            "action": l.get("action_type", l.get("action")),
            "risk_level": l.get("risk_level"),
            "flag_reason": l.get("flag_reason") or l.get("policy_violations"),
            "ai_explanation": l.get("ai_explanation"),
            "ai_compliance_status": l.get("ai_compliance_status"),
            "ai_recommended_action": l.get("ai_recommended_action"),
            "ai_regulatory_refs": l.get("ai_regulatory_refs"),
            "inputs": str(l.get("inputs") or l.get("input", ""))[:200],
            "created_at": l.get("created_at"),
        }
        for l in sample
    ]

    context = (
        f"You are AgentBridge, a fintech compliance AI.\n"
        f"Answer using only the data below. Be specific, cite counts, reference RBI clauses.\n\n"
        f"SUMMARY: total={total}, flagged={len(flagged)}, high_risk={len(high_risk)}, actions={actions}\n\n"
        f"FLAGGED SAMPLES:\n{sample_clean}"
    )

    try:
        r = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": context},
                    {"role": "user", "content": question},
                ],
                "max_tokens": 400,
                "temperature": 0.2,
            },
            timeout=10,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Query failed: {e}"
