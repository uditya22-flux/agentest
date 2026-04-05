from core_ai.dao import DAO
from typing import List, Tuple


# ─────────────────────────────────────────
# RBI FREE-AI CLAUSE DEFINITIONS
# ─────────────────────────────────────────

CLAUSES = {
    "has_reasoning":   "FREE-AI Clause 3.1 — Explainability: Agent must log reasoning for every decision.",
    "has_timestamp":   "FREE-AI Clause 4.2 — Auditability: Every decision must be timestamped.",
    "has_input":       "FREE-AI Clause 2.1 — Data Traceability: Input data must be logged.",
    "has_output":      "FREE-AI Clause 5.0 — Outcome Logging: Decision outcome must be recorded.",
    "has_agent_name":  "FREE-AI Clause 1.3 — Agent Identification: Deciding agent must be identified.",
    "has_session_id":  "FREE-AI Clause 4.4 — Session Traceability: Decisions must be grouped by session.",
    "has_kyc":         "FREE-AI Clause 6.1 — Customer Verification: KYC status must be present for approvals.",
    "has_action_type": "FREE-AI Clause 5.2 — Action Classification: Action type must be a known, classified verb.",
}

VIOLATIONS = {
    "missing_reasoning":   "VIOLATION — FREE-AI Clause 3.1: No reasoning logged. Explainability requirement not met.",
    "missing_timestamp":   "VIOLATION — FREE-AI Clause 4.2: No timestamp. Decision cannot be placed in time.",
    "missing_input":       "VIOLATION — FREE-AI Clause 2.1: No input data. Traceability requirement not met.",
    "missing_output":      "VIOLATION — FREE-AI Clause 5.0: No output recorded. Outcome logging requirement not met.",
    "missing_agent_name":  "VIOLATION — FREE-AI Clause 1.3: Agent not identified.",
    "missing_session_id":  "VIOLATION — FREE-AI Clause 4.4: No session ID. Cannot group decisions into audit trail.",
    "missing_kyc":         "VIOLATION — FREE-AI Clause 6.1: Approval made without KYC status in input.",
    "unknown_action_type": "VIOLATION — FREE-AI Clause 5.2: Action type unknown or unclassified.",
}


# ─────────────────────────────────────────
# MAPPER
# ─────────────────────────────────────────

def map_compliance(dao: DAO) -> DAO:
    tags: List[str] = []
    violations: List[str] = []

    # Clause 3.1 — Explainability
    if dao.reasoning and dao.reasoning.strip():
        tags.append(CLAUSES["has_reasoning"])
    else:
        violations.append(VIOLATIONS["missing_reasoning"])

    # Clause 4.2 — Auditability
    if dao.timestamp:
        tags.append(CLAUSES["has_timestamp"])
    else:
        violations.append(VIOLATIONS["missing_timestamp"])

    # Clause 2.1 — Data Traceability
    if dao.input and isinstance(dao.input, dict) and len(dao.input) > 0:
        tags.append(CLAUSES["has_input"])
    else:
        violations.append(VIOLATIONS["missing_input"])

    # Clause 5.0 — Outcome Logging
    if dao.output and isinstance(dao.output, dict) and len(dao.output) > 0:
        tags.append(CLAUSES["has_output"])
    else:
        violations.append(VIOLATIONS["missing_output"])

    # Clause 1.3 — Agent Identification
    if dao.agent_name and dao.agent_name != "unnamed_agent":
        tags.append(CLAUSES["has_agent_name"])
    else:
        violations.append(VIOLATIONS["missing_agent_name"])

    # Clause 4.4 — Session Traceability
    if dao.session_id and dao.session_id != "session_unknown":
        tags.append(CLAUSES["has_session_id"])
    else:
        violations.append(VIOLATIONS["missing_session_id"])

    # Clause 6.1 — KYC (only checked for approvals)
    if dao.action_type == "approve":
        kyc = dao.input.get("kyc_verified") or dao.input.get("kyc")
        if kyc:
            tags.append(CLAUSES["has_kyc"])
        else:
            violations.append(VIOLATIONS["missing_kyc"])

    # Clause 5.2 — Action Classification
    if dao.action_type and dao.action_type != "unknown":
        tags.append(CLAUSES["has_action_type"])
    else:
        violations.append(VIOLATIONS["unknown_action_type"])

    dao.compliance_tags = tags
    dao.compliance_violations = violations

    return dao