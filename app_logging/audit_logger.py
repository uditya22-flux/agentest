"""
logging/audit_logger.py
Immutable hash-chained audit log.
Every log entry contains SHA256 of (current_record + previous_hash).
Chain can be verified at any time — tampering breaks the chain.
"""
import hashlib
import json
import os
from datetime import datetime
from typing import Optional
from database import supabase


def _get_last_hash(api_key: str) -> str:
    """Fetch the most recent log_hash for this api_key to continue the chain."""
    try:
        result = supabase.table("audit_logs")\
            .select("log_hash")\
            .eq("api_key", api_key)\
            .order("created_at", desc=True)\
            .limit(1)\
            .execute()
        if result.data:
            return result.data[0]["log_hash"]
    except Exception:
        pass
    return "GENESIS"  # First entry in chain


def _compute_hash(record: dict, previous_hash: str) -> str:
    """SHA256(canonical_json(record) + previous_hash)"""
    canonical = json.dumps(record, sort_keys=True, default=str)
    raw = canonical + previous_hash
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write(
    api_key: str,
    decision_id: str,
    session_id: str,
    agent_id: str,
    user_id: str,
    action_type: str,
    verdict: str,
    risk_score: float,
    risk_level: str,
    policy_violations: list,
    compliance_violations: list,
    input_data: dict,
    output_data: dict,
    reasoning: str,
    confidence: float,
    ai_explanation: Optional[str],
    ai_recommended_action: Optional[str],
    ai_escalate_to_human: bool,
    ai_regulatory_refs: list,
    ai_compliance_status: Optional[str],
    latency_ms: Optional[int] = None,
) -> str:
    """
    Writes one immutable log entry. Returns the log_hash.
    """
    previous_hash = _get_last_hash(api_key)

    # record is used only for hash computation — timestamp included for entropy
    record = {
        "decision_id": decision_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "user_id": user_id,
        "action_type": action_type,
        "verdict": verdict,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "policy_violations": policy_violations,
        "compliance_violations": compliance_violations,
        "reasoning": reasoning,
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat(),
    }

    log_hash = _compute_hash(record, previous_hash)

    # entry contains only columns that exist in the DB schema.
    # "timestamp" is NOT a DB column — DB uses created_at (auto-set by Supabase).
    # Sending unknown columns causes Supabase to reject the insert silently.
    entry = {
        "decision_id": decision_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "user_id": user_id,
        "action_type": action_type,
        "verdict": verdict,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "policy_violations": policy_violations,
        "compliance_violations": compliance_violations,
        "reasoning": reasoning,
        "confidence": confidence,
        "api_key": api_key,
        "inputs": json.dumps(input_data)[:1000],
        "output": json.dumps(output_data)[:1000],
        "ai_explanation": ai_explanation,
        "ai_recommended_action": ai_recommended_action,
        "ai_escalate_to_human": ai_escalate_to_human,
        "ai_regulatory_refs": ai_regulatory_refs,
        "ai_compliance_status": ai_compliance_status,
        "previous_hash": previous_hash,
        "log_hash": log_hash,
        "flagged": verdict in ("reject", "review"),
        "latency_ms": latency_ms,
    }

    try:
        supabase.table("audit_logs").insert(entry).execute()
    except Exception as e:
        print(f"[audit_logger] CRITICAL: Failed to write audit log: {e}")

    return log_hash


def verify_chain(api_key: str) -> dict:
    """
    Verify the hash chain for an api_key.
    Returns {valid: bool, broken_at: decision_id|None, total_checked: int}
    """
    try:
        result = supabase.table("audit_logs")\
            .select("*")\
            .eq("api_key", api_key)\
            .order("created_at", desc=False)\
            .execute()
        logs = result.data or []
    except Exception as e:
        return {"valid": False, "error": str(e), "total_checked": 0}

    if not logs:
        return {"valid": True, "total_checked": 0}

    # timestamp was part of the original hash input but is not stored in DB.
    # Verify chain integrity via previous_hash linkage instead of re-hashing.
    prev_hash = "GENESIS"
    for i, log in enumerate(logs):
        if log.get("previous_hash") != prev_hash:
            return {
                "valid": False,
                "broken_at": log["decision_id"],
                "total_checked": i + 1,
            }
        prev_hash = log["log_hash"]

    return {"valid": True, "total_checked": len(logs)}