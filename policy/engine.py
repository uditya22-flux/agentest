"""
policy/engine.py
Hard enforcement rules. These BLOCK decisions before execution.
If a policy rule fails → decision is rejected, agent cannot proceed.
"""
from typing import List, Tuple
from models.schemas import DecisionRequest

# Thresholds
HIGH_VALUE_THRESHOLD = 50000      # INR
CRITICAL_VALUE_THRESHOLD = 200000 # INR — requires EDD under KYC Master Direction
LOW_CONFIDENCE_THRESHOLD = 0.75
CRITICAL_CONFIDENCE_THRESHOLD = 0.50


class PolicyViolation:
    def __init__(self, rule: str, reason: str, severity: str, block: bool):
        self.rule = rule
        self.reason = reason
        self.severity = severity   # warning | critical
        self.block = block         # True = hard reject, False = flag for review


def evaluate(req: DecisionRequest) -> Tuple[str, List[PolicyViolation]]:
    """
    Evaluates all policy rules against the request.
    Returns (verdict, violations)
    verdict: allow | review | reject
    """
    violations: List[PolicyViolation] = []
    amount = req.input.get("amount", 0) or 0
    kyc_verified = req.input.get("kyc_verified") or req.input.get("kyc", False)

    # ── HARD REJECT RULES ──────────────────────────────────────────────────

    # Rule P1: No KYC on approval → hard reject
    if req.action_type == "approve" and not kyc_verified:
        violations.append(PolicyViolation(
            rule="P1_NO_KYC_APPROVAL",
            reason="Approval attempted without KYC verification. Violates RBI KYC Master Direction (CDD obligation) and PMLA Section 12.",
            severity="critical",
            block=True,
        ))

    # Rule P2: Critical value with no EDD markers → hard reject
    if req.action_type == "approve" and amount >= CRITICAL_VALUE_THRESHOLD:
        edd_done = req.input.get("edd_completed") or req.input.get("enhanced_due_diligence")
        if not edd_done:
            violations.append(PolicyViolation(
                rule="P2_CRITICAL_VALUE_NO_EDD",
                reason=f"Transaction of ₹{amount} requires Enhanced Due Diligence under RBI KYC Master Direction. EDD not present in input.",
                severity="critical",
                block=True,
            ))

    # Rule P3: Confidence below critical threshold on approval → hard reject
    if req.action_type == "approve" and req.confidence < CRITICAL_CONFIDENCE_THRESHOLD:
        violations.append(PolicyViolation(
            rule="P3_CRITICAL_LOW_CONFIDENCE",
            reason=f"Agent confidence {req.confidence} is critically low (<{CRITICAL_CONFIDENCE_THRESHOLD}). Approval blocked — violates RBI FREE-AI Sutra 7 (Safety).",
            severity="critical",
            block=True,
        ))

    # ── REVIEW RULES (flag, don't block) ───────────────────────────────────

    # Rule P4: High value + low confidence → review
    if req.action_type == "approve" and amount > HIGH_VALUE_THRESHOLD and req.confidence < LOW_CONFIDENCE_THRESHOLD:
        violations.append(PolicyViolation(
            rule="P4_HIGH_VALUE_LOW_CONFIDENCE",
            reason=f"₹{amount} approval with confidence {req.confidence} below {LOW_CONFIDENCE_THRESHOLD}. Requires human review.",
            severity="warning",
            block=False,
        ))

    # Rule P5: High value without risk assessment → review
    if req.action_type == "approve" and amount > HIGH_VALUE_THRESHOLD:
        risk_assessed = req.input.get("risk_score") or req.input.get("risk_assessed")
        if not risk_assessed:
            violations.append(PolicyViolation(
                rule="P5_HIGH_VALUE_NO_RISK_ASSESSMENT",
                reason=f"₹{amount} approval without a risk score in input. RBI FREE-AI Pillar 4 (Governance) requires documented risk assessment.",
                severity="warning",
                block=False,
            ))

    # Rule P6: PEP flag → always review
    if req.input.get("is_pep") or req.input.get("politically_exposed"):
        violations.append(PolicyViolation(
            rule="P6_PEP_DETECTED",
            reason="Politically Exposed Person detected. Mandatory EDD and human review under PMLA and FATF Recommendation 12.",
            severity="warning",
            block=False,
        ))

    # ── DETERMINE VERDICT ──────────────────────────────────────────────────
    if any(v.block for v in violations):
        verdict = "reject"
    elif violations:
        verdict = "review"
    else:
        verdict = "allow"

    return verdict, violations
