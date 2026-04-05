from core_ai.dao import DAO
from typing import Any, Dict
import uuid
from datetime import datetime


KNOWN_ACTION_TYPES = {"approve", "reject", "flag", "escalate", "query", "review"}


def parse_to_dao(raw_log: Dict[str, Any]) -> DAO:

    # --- Decision ID ---
    decision_id = (
        str(raw_log.get("id"))
        or str(raw_log.get("decision_id"))
        or str(uuid.uuid4())
    )

    # --- Session ID ---
    session_id_raw = (
        raw_log.get("session_id")
        or raw_log.get("run_id")
        or raw_log.get("trace_id")
    )
    session_id = str(session_id_raw) if session_id_raw is not None else "session_unknown"

    # --- Timestamp ---
    timestamp = (
        raw_log.get("timestamp")
        or raw_log.get("ts")
        or raw_log.get("created_at")
        or datetime.utcnow().isoformat()
    )

    # --- Input ---
    input_data = (
        raw_log.get("input")
        or raw_log.get("input_data")
        or raw_log.get("context")
        or {}
    )
    if not isinstance(input_data, dict):
        input_data = {"raw_input": str(input_data)}

    # --- Reasoning ---
    reasoning = (
        raw_log.get("reasoning")
        or raw_log.get("thought")
        or raw_log.get("explanation")
        or raw_log.get("rationale")
        or None
    )

    # --- Output ---
    output_data = (
        raw_log.get("output")
        or raw_log.get("result")
        or raw_log.get("response")
        or {}
    )
    if not isinstance(output_data, dict):
        output_data = {"raw_output": str(output_data)}

    # --- Action Type ---
    action_type = (
        raw_log.get("action_type")
        or raw_log.get("action")
        or output_data.get("action")
        or "unknown"
    )
    if action_type not in KNOWN_ACTION_TYPES:
        action_type = "unknown"

    # --- Agent Name ---
    agent_name = (
        raw_log.get("agent_name")
        or raw_log.get("agent")
        or raw_log.get("model")
        or "unnamed_agent"
    )

    return DAO(
        decision_id=decision_id,
        session_id=session_id,
        timestamp=timestamp,
        input=input_data,
        reasoning=reasoning,
        output=output_data,
        risk_level="low",
        flag_reason=None,
        compliance_tags=[],
        agent_name=agent_name,
        action_type=action_type,
    )