import os
import json
import httpx
from core_ai.dao import DAO

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are a Senior Compliance Analysis Engine specialised in Indian financial services regulation.
You analyse AI agent decision logs on behalf of Chief Compliance Officers (CCOs) at Indian fintech companies.
Your analysis must be accurate, legally grounded, and immediately usable in a regulatory examination.

REGULATORY FRAMEWORKS (current as of 2026):

1. RBI FREE-AI FRAMEWORK (August 13, 2025)
   Seven Sutras: S1-Trust, S2-People First, S3-Innovation, S4-Fairness, S5-Accountability, S6-Explainability, S7-Safety
   Six Pillars: P1-Infrastructure, P2-Policy, P3-Capacity, P4-Governance, P5-Protection, P6-Assurance
   Every AI decision must have a logged human-readable explanation (S6/P4).
   Regulated entities cannot disclaim liability by pointing to the AI vendor (S5).

2. RBI KYC MASTER DIRECTION 2016 (amended August 14, 2025)
   OTP eKYC: 1 lakh/year transaction cap. Video KYC removes this cap.
   STRs must be filed with FIU-IND within 7 days of suspicion.
   High-risk customers require EDD. Beneficial ownership threshold: >10%.
   CKYC upload mandatory within 3 working days. Violation = 1 lakh/day under PMLA.

3. PMLA 2002 (amended 2023/2024)
   Extended to include payment aggregators and payment gateways.
   STR filing within 7 days — failure is a criminal offence.
   Transaction records must be maintained for 5 years minimum.

4. DPDP ACT 2023 + DPDP RULES 2025
   Explicit consent required before processing personal data.
   Purpose limitation: data only used for stated purpose.
   Data minimisation: only necessary data may be processed.
   Penalties: up to 250 crore per breach for SDF governance failures.

5. RBI PAYMENT SECURITY GUIDELINES
   2FA mandatory for all digital payment transactions above threshold.
   Frauds above 1 lakh must be reported to RBI within specified timelines.

6. RBI OUTSOURCING GUIDELINES (November 2023)
   Regulated entity remains fully accountable for third-party AI decisions.
   Must maintain audit rights and override capability over vendor AI.

ANALYSIS INSTRUCTIONS:
1. Identify the actual action taken by the agent.
2. Evaluate against the frameworks above. Cite specific framework and principle.
3. Assess whether compliant, warning, or violation.
4. Write explanation so a CCO can understand immediately: what happened, which rule, what the exposure is.
5. Give concrete recommended actions with timeline if urgent.
6. Assign confidence score 0.0-1.0.

escalate_to_human must be true if:
- risk_level is high or critical
- compliance_status is violation
- confidence_score is below 0.65
- log involves a PEP, sanctions entity, or large transaction

OUTPUT — STRICT JSON ONLY. No markdown. No preamble. No explanation outside JSON.
{
  "action_summary": "One sentence: what the agent did.",
  "compliance_status": "compliant | warning | violation",
  "risk_level": "low | medium | high | critical",
  "category": "KYC | AML | Data Privacy | Auditability | Payment Security | Outsourcing Risk | Explainability | Fairness/Bias | Consumer Protection | Governance | Other",
  "issue_detected": true or false,
  "regulatory_references": ["RBI FREE-AI Sutra 6", "PMLA 2002 - STR filing obligation"],
  "explanation": "2-4 sentences for a CCO in a regulatory examination.",
  "recommended_action": "Specific concrete next steps with timeline.",
  "confidence_score": 0.0,
  "escalate_to_human": true or false
}"""


def _build_prompt(dao: DAO) -> str:
    return (
        f"Agent: {dao.agent_name}\n"
        f"Action type: {dao.action_type}\n"
        f"Input data: {json.dumps(dao.input)}\n"
        f"Reasoning: {dao.reasoning or 'Not provided'}\n"
        f"Output: {json.dumps(dao.output)}\n"
        f"Rule-engine risk level: {dao.risk_level}\n"
        f"Rule-engine flag reason: {dao.flag_reason or 'None'}\n"
        f"Compliance tags: {', '.join(dao.compliance_tags) or 'None'}\n"
        f"Compliance violations: {', '.join(dao.compliance_violations) or 'None'}\n"
    )


def analyze(dao: DAO, api_key: str = None) -> DAO:
    """
    Calls Groq to perform compliance analysis on a DAO.
    Writes all ai_* fields directly onto the DAO and returns it.
    Gracefully skips if no api_key or Groq is unavailable.
    """
    if not api_key:
        api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        dao.ai_explanation = "AI analysis unavailable — GROQ_API_KEY not set."
        dao.ai_compliance_status = "unknown"
        dao.ai_risk_level = dao.risk_level
        dao.ai_escalate_to_human = dao.risk_level in ("high", "critical")
        return dao

    try:
        r = httpx.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_prompt(dao)},
                ],
                "max_tokens": 600,
                "temperature": 0.2,
            },
            timeout=12,
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()

        # Strip markdown fences if model adds them
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())

    except Exception as e:
        dao.ai_explanation = f"AI analysis failed: {e}"
        dao.ai_compliance_status = "unknown"
        dao.ai_risk_level = dao.risk_level
        dao.ai_escalate_to_human = dao.risk_level in ("high", "critical")
        return dao

    dao.ai_action_summary     = result.get("action_summary")
    dao.ai_compliance_status  = result.get("compliance_status")
    dao.ai_risk_level         = result.get("risk_level")
    dao.ai_category           = result.get("category")
    dao.ai_issue_detected     = result.get("issue_detected")
    dao.ai_explanation        = result.get("explanation")
    dao.ai_recommended_action = result.get("recommended_action")
    dao.ai_confidence_score   = result.get("confidence_score")
    dao.ai_regulatory_refs    = result.get("regulatory_references", [])
    dao.ai_escalate_to_human  = result.get("escalate_to_human", False)
    dao.ai_raw_response       = result
    return dao
