from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

@dataclass
class DAO:
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    input: Dict[str, Any] = field(default_factory=dict)
    reasoning: Optional[str] = None
    output: Dict[str, Any] = field(default_factory=dict)

    risk_level: str = "low"
    flag_reason: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)

    agent_name: str = ""
    action_type: str = ""

    ai_reasoning: Optional[str] = None
    ai_action_summary: Optional[str] = None
    ai_compliance_status: Optional[str] = None
    ai_risk_level: Optional[str] = None
    ai_category: Optional[str] = None
    ai_issue_detected: Optional[bool] = None
    ai_explanation: Optional[str] = None
    ai_recommended_action: Optional[str] = None
    ai_confidence_score: Optional[float] = None
    ai_regulatory_refs: List[str] = field(default_factory=list)
    ai_escalate_to_human: bool = False
    ai_raw_response: Optional[Dict] = None
