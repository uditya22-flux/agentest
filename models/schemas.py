"""
Strict Pydantic schemas — nothing enters the system without passing these.
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
import uuid


class DecisionRequest(BaseModel):
    """Incoming request to the decision gateway. All fields mandatory."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1)
    input: Dict[str, Any] = Field(...)
    reasoning: str = Field(default="")
    confidence: float = Field(..., ge=0.0, le=1.0)
    output: Dict[str, Any] = Field(default_factory=dict)
    domain: str = Field(default="fintech")
    api_key: str = Field(..., min_length=1)



    @validator("action_type")
    def action_type_known(cls, v):
        known = {"approve", "reject", "flag", "escalate", "query", "review"}
        if v not in known:
            raise ValueError(f"action_type must be one of {known}")
        return v


class DecisionResponse(BaseModel):
    decision_id: str
    verdict: str                    # allow | review | reject
    risk_score: float
    risk_level: str                 # low | medium | high | critical
    policy_violations: List[str]
    compliance_violations: List[str]
    ai_explanation: Optional[str]
    ai_recommended_action: Optional[str]
    escalate_to_human: bool
    log_hash: str
    message: str


class RejectedDecision(BaseModel):
    decision_id: str
    verdict: str = "reject"
    blocked_at: str                 # validation | policy | risk
    reason: str
    policy_rule: Optional[str]
    risk_score: Optional[float]
    log_hash: str
    message: str = "Decision blocked by AgentBridge compliance gateway"
