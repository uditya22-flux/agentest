from core_ai.dao import DAO
from typing import List, Callable


# --- Rule type: each rule is a function that takes a DAO and mutates it ---
Rule = Callable[[DAO], DAO]


# ─────────────────────────────────────────
# RULES
# ─────────────────────────────────────────

def rule_high_value_no_flag(dao: DAO) -> DAO:
    """
    High-value transaction approved without any risk flag.
    RBI expects extra scrutiny on large approvals.
    """
    amount = dao.input.get("amount") or dao.output.get("amount") or 0
    if amount > 50000 and dao.action_type == "approve" and dao.risk_level == "low":
        dao.risk_level = "high"
        dao.flag_reason = (
            f"High-value transaction of ₹{amount} approved with no risk flag."
        )
    return dao


def rule_missing_reasoning(dao: DAO) -> DAO:
    """
    Agent made a decision but logged no reasoning.
    Violates FREE-AI explainability requirement.
    """
    if dao.reasoning is None or dao.reasoning.strip() == "":
        if dao.risk_level != "high":
            dao.risk_level = "medium"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + " | Agent decision logged with no reasoning or explanation."
        )
    return dao


def rule_approve_without_kyc(dao: DAO) -> DAO:
    """
    Agent approved something but KYC was not verified in the input.
    Classic compliance gap RBI looks for.
    """
    kyc_verified = dao.input.get("kyc_verified") or dao.input.get("kyc")
    if dao.action_type == "approve" and not kyc_verified:
        dao.risk_level = "high"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + " | Approval made without KYC verification in input data."
        )
    return dao


def rule_unknown_action_type(dao: DAO) -> DAO:
    """
    Agent performed an action that doesn't match any known action type.
    Could mean the agent is doing something untracked.
    """
    if dao.action_type == "unknown":
        if dao.risk_level == "low":
            dao.risk_level = "medium"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + " | Action type could not be identified. Untracked agent behavior."
        )
    return dao


def rule_low_confidence_approval(dao: DAO) -> DAO:
    """
    Agent approved but its own confidence score was below threshold.
    Agent is approving things it isn't sure about.
    """
    confidence = dao.output.get("confidence") or dao.output.get("score") or 1.0
    if dao.action_type == "approve" and float(confidence) < 0.75:
        if dao.risk_level != "high":
            dao.risk_level = "medium"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + f" | Agent approved with low confidence score of {confidence}."
        )
    return dao


def rule_repeated_rejections(dao: DAO) -> DAO:
    """
    Placeholder for future: detect if same user_id is being rejected
    repeatedly across sessions — potential bias or targeting pattern.
    Currently flags if reject count in output exceeds threshold.
    """
    reject_count = dao.output.get("consecutive_rejections") or 0
    if dao.action_type == "reject" and int(reject_count) >= 3:
        if dao.risk_level == "low":
            dao.risk_level = "medium"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + f" | User has been rejected {reject_count} times consecutively. Possible bias pattern."
        )
    return dao


def rule_structural_detection(dao: DAO) -> DAO:
    """
    Structural check for reasoning and log completeness.
    Focused on high-stakes decisions (approve/reject).
    """
    is_high_stakes = dao.action_type in ("approve", "reject", "escalate")
    reasoning = (dao.reasoning or "").lower()
    
    # 🔍 1. Weak Reasoning Detection (Strict for high-stakes)
    lazy_phrases = ["no reasoning", "none", "not provided", "test", "demo", "as requested", "ok", "approve"]
    is_lazy = any(p in reasoning for p in lazy_phrases) or len(reasoning.split()) < 4
    
    if is_lazy and reasoning != "" and is_high_stakes:
        if dao.risk_level == "low":
            dao.risk_level = "medium"
        dao.flag_reason = (
            (dao.flag_reason or "")
            + " | STRUCTURAL_ISSUE: High-stakes decision lacks descriptive reasoning."
        )

    # 🔍 2. Data Synchronization/Completeness
    if is_high_stakes:
        mandatory_context = ["amount", "kyc_verified"]
        missing = [f for f in mandatory_context if f not in dao.input and f not in dao.output]
        if missing:
            dao.risk_level = "high"
            dao.flag_reason = (
                (dao.flag_reason or "")
                + f" | STRUCTURAL_ISSUE: Decision data desync - missing mandatory fields: {missing}"
            )

    return dao


# ─────────────────────────────────────────
# REGISTRY — add new rules here
# ─────────────────────────────────────────

RULES: List[Rule] = [
    rule_high_value_no_flag,
    rule_missing_reasoning,
    rule_approve_without_kyc,
    rule_unknown_action_type,
    rule_low_confidence_approval,
    rule_repeated_rejections,
    rule_structural_detection,
]



# ─────────────────────────────────────────
# MAIN FUNCTION — called by pipeline.py
# ─────────────────────────────────────────

def check_anomalies(dao: DAO) -> DAO:
    for rule in RULES:
        dao = rule(dao)
    return dao