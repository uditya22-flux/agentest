"""
risk/scorer.py
Deterministic risk scoring with weights.
Score: 0.0 (no risk) → 1.0 (critical risk)
Thresholds: allow <0.35 | review 0.35–0.65 | reject >0.65
"""
from models.schemas import DecisionRequest
from database import supabase


# ── WEIGHTS ────────────────────────────────────────────────────────────────
W_NO_KYC           = 0.35   # Hard: no KYC on approval
W_HIGH_VALUE       = 0.20   # Amount > ₹50,000
W_CRITICAL_VALUE   = 0.35   # Amount > ₹2,00,000
W_LOW_CONFIDENCE   = 0.15   # Confidence < 0.75
W_CRIT_CONFIDENCE  = 0.30   # Confidence < 0.50
W_NO_RISK_SCORE    = 0.10   # No risk_score in input
W_PEP              = 0.25   # Politically exposed person
W_SESSION_HISTORY  = 0.15   # Prior high-risk decisions in session
W_UNKNOWN_ACTION   = 0.10   # Unclassified action type
W_STRUCTURAL_GAP   = 0.20   # Missing/Lazy reasoning or context

# ── THRESHOLDS ─────────────────────────────────────────────────────────────
ALLOW_THRESHOLD  = 0.35
REVIEW_THRESHOLD = 0.65


def _session_risk_multiplier(session_id: str) -> float:
    """
    Stateful risk: query Supabase for prior high-risk decisions in this session.
    Returns a score addition of up to 0.15 based on session history.
    """
    try:
        result = supabase.table("audit_logs")\
            .select("risk_level")\
            .eq("session_id", session_id)\
            .in_("risk_level", ["high", "critical"])\
            .limit(10)\
            .execute()
        count = len(result.data or [])
        # Each prior high-risk decision adds 0.03, capped at 0.15
        return min(count * 0.03, W_SESSION_HISTORY)
    except Exception:
        return 0.0


def score(req: DecisionRequest) -> tuple[float, str, str]:
    """
    Returns (risk_score, risk_level, explanation)
    """
    amount = req.input.get("amount", 0) or 0
    kyc_verified = req.input.get("kyc_verified") or req.input.get("kyc", False)
    risk_score = 0.0
    factors = []

    if req.action_type == "approve" and not kyc_verified:
        risk_score += W_NO_KYC
        factors.append(f"+{W_NO_KYC} no KYC")

    if amount >= 200000:
        risk_score += W_CRITICAL_VALUE
        factors.append(f"+{W_CRITICAL_VALUE} critical value ₹{amount}")
    elif amount >= 50000:
        risk_score += W_HIGH_VALUE
        factors.append(f"+{W_HIGH_VALUE} high value ₹{amount}")

    if req.confidence < 0.50:
        risk_score += W_CRIT_CONFIDENCE
        factors.append(f"+{W_CRIT_CONFIDENCE} critical confidence {req.confidence}")
    elif req.confidence < 0.75:
        risk_score += W_LOW_CONFIDENCE
        factors.append(f"+{W_LOW_CONFIDENCE} low confidence {req.confidence}")

    if not req.input.get("risk_score") and not req.input.get("risk_assessed"):
        risk_score += W_NO_RISK_SCORE
        factors.append(f"+{W_NO_RISK_SCORE} no risk assessment")

    if req.input.get("is_pep") or req.input.get("politically_exposed"):
        risk_score += W_PEP
        factors.append(f"+{W_PEP} PEP detected")

    # 🔍 Structural Detection in Scorer (High-stakes only)
    if req.action_type in ("approve", "reject", "escalate"):
        reasoning = (req.reasoning or "").lower()
        lazy_phrases = ["no reasoning", "none", "not provided", "test", "demo", "as requested", "ok", "approve"]
        is_lazy = any(p in reasoning for p in lazy_phrases) or len(reasoning.split()) < 4
        if is_lazy:
            risk_score += W_STRUCTURAL_GAP
            factors.append(f"+{W_STRUCTURAL_GAP} structural gap: weak reasoning on high-stakes decision")

    # Stateful: session history

    session_add = _session_risk_multiplier(req.session_id)
    if session_add > 0:
        risk_score += session_add
        factors.append(f"+{session_add:.2f} session history")

    risk_score = round(min(risk_score, 1.0), 3)

    if risk_score >= REVIEW_THRESHOLD:
        risk_level = "critical" if risk_score >= 0.85 else "high"
    elif risk_score >= ALLOW_THRESHOLD:
        risk_level = "medium"
    else:
        risk_level = "low"

    explanation = f"Risk score {risk_score}: " + ", ".join(factors) if factors else f"Risk score {risk_score}: no risk factors detected"

    return risk_score, risk_level, explanation
