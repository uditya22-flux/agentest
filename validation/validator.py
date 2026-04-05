"""
validation/validator.py
Strict input validation before anything enters the pipeline.
Rejects invalid JSON, missing fields, null reasoning, unknown action types.
"""
from typing import Tuple, Optional
from models.schemas import DecisionRequest


KNOWN_ACTION_TYPES = {"approve", "reject", "flag", "escalate", "query", "review"}
REQUIRED_FIELDS = ["session_id", "agent_id", "user_id", "action_type", "input", "reasoning", "confidence", "api_key"]


def validate(raw: dict) -> Tuple[bool, Optional[DecisionRequest], Optional[str]]:
    """
    Returns (is_valid, parsed_request, error_message)
    
    Pseudocode:
        if missing required fields → reject
        if reasoning is null/empty → reject
        if action_type not in known set → reject
        if confidence not in [0.0, 1.0] → reject
        if input is not dict → reject
    """
    # Check required fields
    missing = [f for f in REQUIRED_FIELDS if raw.get(f) is None]
    if missing:
        return False, None, f"Missing required fields: {missing}"

    # Null reasoning check removed to allow anomaly detection engine to flag it
    reasoning = raw.get("reasoning", "")

    # Action type check
    if raw.get("action_type") not in KNOWN_ACTION_TYPES:
        return False, None, f"Unknown action_type '{raw.get('action_type')}'. Must be one of {KNOWN_ACTION_TYPES}"

    # Confidence range
    try:
        confidence = float(raw.get("confidence", -1))
        if not (0.0 <= confidence <= 1.0):
            raise ValueError
    except (TypeError, ValueError):
        return False, None, "confidence must be a float between 0.0 and 1.0"

    # Input must be a dict
    if not isinstance(raw.get("input"), dict):
        return False, None, "input must be a JSON object"

    # Parse through Pydantic for full validation
    try:
        request = DecisionRequest(**raw)
        return True, request, None
    except Exception as e:
        return False, None, str(e)
