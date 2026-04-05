"""
POST /log-manual — v2
Allows a user to submit a log directly from the UI.
Runs the full gateway pipeline AND enriches the response with:
  - Behavioral drift analysis (if enough history exists)
  - Structuring detection (across recent logs for this api_key)
  - Groq deep-analysis of drift and structuring findings
  - Detailed per-section report block ready for the PDF report generator
"""
import os
import uuid
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from gateway.decision_gateway import process_decision
from core_ai.behavioral_drift import detect_drift
from core_ai.structuring_detector import detect_structuring
from core_ai.groq_reasoning import analyze_drift_with_groq, analyze_structuring_with_groq

router = APIRouter()


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _fetch_recent_logs(api_key: str, limit: int = 100) -> list:
    """
    Pulls recent logs for this api_key from the database.
    Returns [] gracefully if DB is unavailable.
    """
    try:
        from database import get_db
        db = next(get_db())
        from sqlalchemy import text
        rows = db.execute(
            text(
                "SELECT * FROM audit_logs WHERE api_key = :key "
                "ORDER BY created_at DESC LIMIT :limit"
            ),
            {"key": api_key, "limit": limit},
        ).fetchall()
        return [dict(row._mapping) for row in rows]
    except Exception:
        return []


def _normalize(data: dict) -> dict:
    """Maps flexible UI field names to gateway schema."""
    raw = dict(data)
    if "agent_name" in raw and "agent_id" not in raw:
        raw["agent_id"] = raw.pop("agent_name")
    if "action" in raw and "action_type" not in raw:
        raw["action_type"] = raw.pop("action")
    if "inputs" in raw and "input" not in raw:
        v = raw.pop("inputs")
        raw["input"] = v if isinstance(v, dict) else {}
    if "input" not in raw or not isinstance(raw.get("input"), dict):
        raw["input"] = {}
    if not raw.get("session_id"):
        raw["session_id"] = f"ui-session-{str(uuid.uuid4())[:8]}"
    if not raw.get("user_id"):
        raw["user_id"] = "ui_user"
    if "confidence" not in raw:
        raw["confidence"] = 0.85
    if not raw.get("reasoning"):
        raw["reasoning"] = "Submitted via AgentBridge UI"
    return raw


# ─────────────────────────────────────────────────────────────
# ENDPOINT
# ─────────────────────────────────────────────────────────────

@router.post("/log-manual")
async def manual_log(data: dict):
    """
    Submit a log entry from the UI.
    Returns full compliance verdict + drift analysis + structuring scan
    + Groq deep-analysis narrative for the report.
    """
    if not data.get("api_key"):
        raise HTTPException(status_code=400, detail="api_key required")

    raw = _normalize(data)
    api_key = raw["api_key"]
    agent_name = raw.get("agent_id", "")

    # ── Step 1: Core gateway decision ──────────────────────────────────────
    response_data, status_code = process_decision(raw)

    # ── Step 2: Pull recent log history for this api_key ───────────────────
    recent_logs = _fetch_recent_logs(api_key, limit=200)

    # ── Step 3: Behavioral drift detection ─────────────────────────────────
    drift_result = detect_drift(recent_logs, agent_name=agent_name)

    # ── Step 4: Structuring detection ─────────────────────────────────────
    structuring_result = detect_structuring(recent_logs)

    # ── Step 5: Groq deep analysis of drift (if findings exist) ────────────
    groq_api_key = os.environ.get("GROQ_API_KEY", "")
    drift_ai_narrative = None
    if drift_result.get("status") == "drift_detected" and drift_result.get("groq_context"):
        drift_ai_narrative = analyze_drift_with_groq(
            drift_result["groq_context"], api_key=groq_api_key
        )

    # ── Step 6: Groq deep analysis of structuring findings ─────────────────
    structuring_ai_narratives = []
    if structuring_result.get("groq_contexts"):
        structuring_ai_narratives = analyze_structuring_with_groq(
            structuring_result["groq_contexts"], api_key=groq_api_key
        )

    # ── Step 7: Build enriched report block ────────────────────────────────
    report_block = _build_report_block(
        response_data=response_data,
        drift_result=drift_result,
        drift_ai_narrative=drift_ai_narrative,
        structuring_result=structuring_result,
        structuring_ai_narratives=structuring_ai_narratives,
        agent_name=agent_name,
        api_key=api_key,
    )

    # ── Step 8: Return merged response ─────────────────────────────────────
    response_data["drift_analysis"] = {
        "status": drift_result.get("status"),
        "overall_severity": drift_result.get("overall_severity"),
        "finding_count": drift_result.get("finding_count", 0),
        "findings": drift_result.get("findings", []),
        "this_week": drift_result.get("this_week"),
        "last_week": drift_result.get("last_week"),
        "ai_narrative": drift_ai_narrative,
    }
    response_data["structuring_analysis"] = {
        "overall_severity": structuring_result.get("overall_severity"),
        "str_required": structuring_result.get("str_required", False),
        "finding_count": structuring_result.get("finding_count", 0),
        "findings": [
            {
                "pattern": f.get("pattern"),
                "severity": f.get("severity"),
                "str_trigger": f.get("str_trigger"),
                "description": f.get("description"),
                "rbi_reference": f.get("rbi_reference"),
                "flagged_decisions": f.get("flagged_decisions", []),
            }
            for f in structuring_result.get("findings", [])
        ],
        "ai_narratives": structuring_ai_narratives,
        "summary": structuring_result.get("summary"),
    }
    response_data["report_block"] = report_block

    return JSONResponse(content=response_data, status_code=status_code)


# ─────────────────────────────────────────────────────────────
# REPORT BLOCK BUILDER
# ─────────────────────────────────────────────────────────────

def _build_report_block(
    response_data: dict,
    drift_result: dict,
    drift_ai_narrative,
    structuring_result: dict,
    structuring_ai_narratives: list,
    agent_name: str,
    api_key: str,
) -> dict:
    """
    Assembles a detailed report block that the report_generator.py
    can consume directly when a CCO requests a PDF report.
    """
    from datetime import datetime

    sections = []

    # Section 1: Decision verdict
    sections.append({
        "section": "Decision Verdict",
        "verdict": response_data.get("verdict"),
        "risk_level": response_data.get("risk_level"),
        "risk_score": response_data.get("risk_score"),
        "ai_explanation": response_data.get("ai_explanation"),
        "ai_recommended_action": response_data.get("ai_recommended_action"),
        "escalate_to_human": response_data.get("escalate_to_human"),
        "policy_violations": response_data.get("policy_violations", []),
        "compliance_violations": response_data.get("compliance_violations", []),
    })

    # Section 2: Behavioral drift
    drift_section = {
        "section": "Behavioral Drift Analysis",
        "status": drift_result.get("status", "unknown"),
        "overall_severity": drift_result.get("overall_severity", "unknown"),
        "finding_count": drift_result.get("finding_count", 0),
        "this_week_stats": drift_result.get("this_week"),
        "last_week_stats": drift_result.get("last_week"),
        "findings": drift_result.get("findings", []),
        "ai_narrative": drift_ai_narrative or "No drift findings to analyse.",
    }
    if drift_result.get("status") == "insufficient_data":
        drift_section["note"] = drift_result.get("message")
    sections.append(drift_section)

    # Section 3: Structuring detection
    str_findings_with_ai = []
    for i, f in enumerate(structuring_result.get("findings", [])):
        str_findings_with_ai.append({
            "pattern": f.get("pattern"),
            "severity": f.get("severity"),
            "str_trigger": f.get("str_trigger"),
            "description": f.get("description"),
            "rbi_reference": f.get("rbi_reference"),
            "flagged_decisions": f.get("flagged_decisions", []),
            "ai_analysis": structuring_ai_narratives[i] if i < len(structuring_ai_narratives) else None,
        })

    sections.append({
        "section": "Structuring & AML Pattern Detection",
        "overall_severity": structuring_result.get("overall_severity", "clean"),
        "str_required": structuring_result.get("str_required", False),
        "str_deadline": "File with FIU-IND within 7 days of suspicion (PMLA 2002)" if structuring_result.get("str_required") else None,
        "finding_count": structuring_result.get("finding_count", 0),
        "findings": str_findings_with_ai,
        "summary": structuring_result.get("summary"),
    })

    # Section 4: RBI compliance summary
    highest_severity = "low"
    for s in [drift_result.get("overall_severity"), structuring_result.get("overall_severity")]:
        if s in ("critical", "high"):
            highest_severity = "critical" if s == "critical" else "high"
            break
        elif s == "medium" and highest_severity == "low":
            highest_severity = "medium"

    rbi_summary = {
        "section": "RBI Compliance Summary",
        "frameworks_evaluated": [
            "RBI FREE-AI Framework (Aug 2025)",
            "RBI KYC Master Direction (Aug 2025)",
            "PMLA 2002 (amended 2023/2024)",
            "DPDP Act 2023 + Rules 2025",
            "RBI Outsourcing Guidelines (Nov 2023)",
        ],
        "overall_compliance_risk": highest_severity,
        "immediate_actions_required": [],
    }
    if structuring_result.get("str_required"):
        rbi_summary["immediate_actions_required"].append(
            "FILE STR with FIU-IND within 7 days — PMLA 2002 Section 12"
        )
    if drift_result.get("overall_severity") in ("high", "critical"):
        rbi_summary["immediate_actions_required"].append(
            "Escalate behavioral drift findings to CCO for review — RBI FREE-AI Sutra 5"
        )
    if response_data.get("escalate_to_human"):
        rbi_summary["immediate_actions_required"].append(
            "Human review mandatory for this decision — risk level exceeds auto-approval threshold"
        )
    sections.append(rbi_summary)

    return {
        "report_generated_at": datetime.utcnow().isoformat(),
        "agent_name": agent_name,
        "api_key_prefix": api_key[:8] + "***" if api_key else "unknown",
        "sections": sections,
    }
