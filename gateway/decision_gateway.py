"""
gateway/decision_gateway.py
Central enforcement point. ALL decisions flow through here.
No bypass possible — this is the only entry point.

Flow:
  1. Validate schema (reject on failure)
  2. Score risk (stateful)
  3. Enforce policies (hard reject or flag)
  4. Run AI compliance analysis
  5. Write immutable audit log
  6. Return structured verdict to agent
"""
import os
import time
from models.schemas import DecisionRequest, DecisionResponse, RejectedDecision
from validation.validator import validate
from policy.engine import evaluate
from risk.scorer import score
from app_logging.audit_logger import write as audit_write
from core_ai.pipeline import process as ai_process


def process_decision(raw: dict) -> tuple[dict, int]:
    """
    Main gateway function. Returns (response_dict, http_status_code).
    
    Called by POST /decide endpoint only.
    """

    # ── TIMING ─────────────────────────────────────────────────────────────
    _start = time.time()

    # ── STEP 1: VALIDATION ─────────────────────────────────────────────────
    is_valid, req, error = validate(raw)
    if not is_valid:
        log_hash = audit_write(
            api_key=raw.get("api_key", "unknown"),
            decision_id=raw.get("decision_id", "unknown"),
            session_id=raw.get("session_id", "unknown"),
            agent_id=raw.get("agent_id", "unknown"),
            user_id=raw.get("user_id", "unknown"),
            action_type=raw.get("action_type", "unknown"),
            verdict="reject",
            risk_score=1.0,
            risk_level="critical",
            policy_violations=[f"VALIDATION_FAILED: {error}"],
            compliance_violations=[],
            input_data=raw.get("input", {}),
            output_data=raw.get("output", {}),
            reasoning=raw.get("reasoning", ""),
            confidence=0.0,
            ai_explanation=None,
            ai_recommended_action=None,
            ai_escalate_to_human=True,
            ai_regulatory_refs=[],
            ai_compliance_status="violation",
            latency_ms=int((time.time() - _start) * 1000),
        )
        return RejectedDecision(
            decision_id=raw.get("decision_id", "unknown"),
            blocked_at="validation",
            reason=error,
            policy_rule=None,
            risk_score=None,
            log_hash=log_hash,
        ).dict(), 422

    # ── STEP 2: RISK SCORING ───────────────────────────────────────────────
    risk_score, risk_level, risk_explanation = score(req)

    # ── STEP 3: POLICY ENFORCEMENT ─────────────────────────────────────────
    policy_verdict, policy_violations = evaluate(req)
    blocking_violations = [v for v in policy_violations if v.block]

    if blocking_violations:
        blocker = blocking_violations[0]
        log_hash = audit_write(
            api_key=req.api_key,
            decision_id=req.decision_id,
            session_id=req.session_id,
            agent_id=req.agent_id,
            user_id=req.user_id,
            action_type=req.action_type,
            verdict="reject",
            risk_score=risk_score,
            risk_level=risk_level,
            policy_violations=[v.reason for v in policy_violations],
            compliance_violations=[],
            input_data=req.input,
            output_data=req.output,
            reasoning=req.reasoning,
            confidence=req.confidence,
            ai_explanation=None,
            ai_recommended_action=f"Human review required: {blocker.rule}",
            ai_escalate_to_human=True,
            ai_regulatory_refs=[],
            ai_compliance_status="violation",
            latency_ms=int((time.time() - _start) * 1000),
        )
        return RejectedDecision(
            decision_id=req.decision_id,
            blocked_at="policy",
            reason=blocker.reason,
            policy_rule=blocker.rule,
            risk_score=risk_score,
            log_hash=log_hash,
        ).dict(), 403

    # ── STEP 4: AI COMPLIANCE ANALYSIS ────────────────────────────────────
    dao = ai_process(req.dict())
    final_verdict = policy_verdict  # allow | review

    # Override to review if risk score is in review zone
    from risk.scorer import ALLOW_THRESHOLD
    if risk_score >= ALLOW_THRESHOLD and final_verdict == "allow":
        final_verdict = "review"

    # CRITICAL: Override if AI detects a violation or high risk
    if dao.ai_compliance_status == "violation":
        final_verdict = "review"  # AI says violation, must review
    
    if dao.ai_risk_level in ("high", "critical") and final_verdict == "allow":
        final_verdict = "review"


    # ── STEP 5: IMMUTABLE AUDIT LOG ────────────────────────────────────────
    # Use AI risk level if it's more severe than the deterministic level
    severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    final_risk_level = risk_level
    if dao.ai_risk_level and severity_map.get(dao.ai_risk_level, 0) > severity_map.get(risk_level, 0):
        final_risk_level = dao.ai_risk_level

    log_hash = audit_write(
        api_key=req.api_key,
        decision_id=req.decision_id,
        session_id=req.session_id,
        agent_id=req.agent_id,
        user_id=req.user_id,
        action_type=req.action_type,
        verdict=final_verdict,
        risk_score=risk_score,
        risk_level=final_risk_level,
        policy_violations=[v.reason for v in policy_violations],
        compliance_violations=dao.compliance_violations,
        input_data=req.input,
        output_data=req.output,
        reasoning=req.reasoning,
        confidence=req.confidence,
        ai_explanation=dao.ai_explanation,
        ai_recommended_action=dao.ai_recommended_action,
        ai_escalate_to_human=dao.ai_escalate_to_human,
        ai_regulatory_refs=dao.ai_regulatory_refs,
        ai_compliance_status=dao.ai_compliance_status,
        latency_ms=int((time.time() - _start) * 1000),
    )

    # ── STEP 6: RETURN VERDICT ─────────────────────────────────────────────
    # If final_verdict is review/reject, return appropriate message
    display_verdict = final_verdict.upper()
    if dao.ai_compliance_status == "violation":
        display_verdict = "REVIEW (VIOLATION)"
    
    http_code = 200 if final_verdict == "allow" else 202  # 202 = proceed with caution
    return DecisionResponse(
        decision_id=req.decision_id,
        verdict=final_verdict,
        risk_score=risk_score,
        risk_level=final_risk_level,
        policy_violations=[v.reason for v in policy_violations],
        compliance_violations=dao.compliance_violations,
        ai_explanation=dao.ai_explanation or risk_explanation,
        ai_recommended_action=dao.ai_recommended_action,
        escalate_to_human=dao.ai_escalate_to_human or (final_risk_level in ("high", "critical")),
        log_hash=log_hash,
        message=f"Decision {display_verdict} — logged and audited",
    ).dict(), http_code