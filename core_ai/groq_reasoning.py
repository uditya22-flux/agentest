"""
groq_reasoning.py — v2
Standalone Groq call for manual-log submissions where the agent
provided no reasoning. Now also accepts drift/structuring context blocks
to produce a detailed, regulation-grounded narrative.
"""
import os
import httpx
from core_ai.dao import DAO

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """\
You are a Senior Compliance Analysis Engine for Indian financial services.
You review AI agent decisions on behalf of Chief Compliance Officers (CCOs).

Regulatory frameworks you must apply (current as of 2026):
- RBI FREE-AI Framework (Aug 2025): 7 Sutras (S1-Trust … S7-Safety), 6 Pillars
- RBI KYC Master Direction (Aug 2025): OTP eKYC cap, Video KYC, EDD, CKYC
- PMLA 2002 (amended 2023/2024): STR within 7 days, 5-year records
- DPDP Act 2023 + Rules 2025: consent, purpose limitation, penalties up to ₹250 Cr
- RBI Payment Security Guidelines: 2FA, fraud reporting timelines
- RBI Outsourcing Guidelines (Nov 2023): regulated entity accountability for vendor AI

Rules:
1. Be specific — cite the exact Sutra, Section, or Clause number.
2. Write for a CCO who needs to act, not an academic.
3. If an STR is required, say so explicitly with the 7-day deadline.
4. Recommend concrete next steps with timelines.
5. Be concise: 3–5 sentences maximum.
"""


def generate_reasoning(dao: DAO, extra_context: str = "") -> str:
    """
    Generates compliance reasoning for a DAO that has no agent-provided reasoning.
    extra_context: optional drift or structuring Groq context block to append.
    """
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return "AI reasoning unavailable — GROQ_API_KEY not set."

    user_content = (
        f"Agent: {dao.agent_name}\n"
        f"Action: {dao.action_type}\n"
        f"Input data: {dao.input}\n"
        f"Output: {dao.output}\n"
        f"Rule-engine risk level: {dao.risk_level}\n"
        f"Rule-engine flags: {dao.flag_reason or 'None'}\n"
        f"Compliance tags: {', '.join(dao.compliance_tags) or 'None'}\n"
        f"Compliance violations: {', '.join(dao.compliance_violations) or 'None'}\n"
    )
    if extra_context:
        user_content += f"\n\nADDITIONAL CONTEXT:\n{extra_context}\n"

    user_content += (
        "\nThe agent provided no reasoning. "
        "Explain what likely happened and why this is risky from an RBI compliance perspective. "
        "Cite specific framework references. Recommend next steps."
    )

    try:
        r = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "max_tokens": 400,
                "temperature": 0.2,
            },
            timeout=12,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"AI reasoning generation failed: {e}"


def analyze_drift_with_groq(groq_context: str, api_key: str = "") -> str:
    """
    Sends a behavioral drift context block to Groq for deep analysis.
    Returns a structured compliance narrative string.
    """
    api_key = api_key or os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return "Drift AI analysis unavailable — GROQ_API_KEY not set."

    try:
        r = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": groq_context},
                ],
                "max_tokens": 800,
                "temperature": 0.15,
            },
            timeout=20,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"Drift AI analysis failed: {e}"


def analyze_structuring_with_groq(groq_contexts: list, api_key: str = "") -> list:
    """
    For each structuring finding context block, calls Groq and returns analysis strings.
    Returns list of analysis strings in the same order as groq_contexts.
    """
    api_key = api_key or os.environ.get("GROQ_API_KEY", "")
    results = []
    for ctx in groq_contexts:
        if not api_key:
            results.append("Structuring AI analysis unavailable — GROQ_API_KEY not set.")
            continue
        try:
            r = httpx.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": ctx},
                    ],
                    "max_tokens": 500,
                    "temperature": 0.15,
                },
                timeout=15,
            )
            r.raise_for_status()
            results.append(r.json()["choices"][0]["message"]["content"].strip())
        except Exception as e:
            results.append(f"Structuring pattern AI analysis failed: {e}")
    return results
