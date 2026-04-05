from fastapi import APIRouter
from database import supabase
from app_logging.audit_logger import verify_chain
from core_ai.dao import DAO
from core_ai.report_generator import generate_report
from core_ai.behavioral_drift import detect_drift
from core_ai.structuring_detector import detect_structuring
import ast, os

router = APIRouter()


def _parse(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        return ast.literal_eval(str(raw))
    except Exception:
        return {}


def _full(log: dict) -> dict:
    """Return all fields the dashboard needs — no stripping."""
    return {
        "decision_id":          log.get("decision_id") or "—",
        "agent_id":             log.get("agent_id") or "—",
        "verdict":              log.get("verdict") or "—",
        "action_type":          log.get("action_type") or "—",
        "risk_level":           log.get("risk_level") or "low",
        "risk_score":           log.get("risk_score"),
        "flagged":              bool(log.get("flagged")),
        "flag_reason":          log.get("flag_reason") or log.get("reasoning"),
        "latency_ms":           log.get("latency_ms"),
        "session_id":           log.get("session_id") or "—",
        "user_id":              log.get("user_id") or "—",
        "created_at":           log.get("created_at"),
        "reasoning":            log.get("reasoning") or "",
        "inputs":               _parse(log.get("inputs")),
        "output":               _parse(log.get("output")),
        "compliance_tags":      log.get("compliance_tags") or [],
        "compliance_violations":log.get("compliance_violations") or [],
        "policy_violations":    log.get("policy_violations") or [],
        "ai_explanation":       log.get("ai_explanation"),
        "ai_recommended_action":log.get("ai_recommended_action"),
        "ai_escalate_to_human": log.get("ai_escalate_to_human", False),
        "ai_compliance_status": log.get("ai_compliance_status"),
        "ai_risk_level":        log.get("ai_risk_level"),
        "confidence":           log.get("confidence"),
    }


@router.get("/logs")
async def get_logs(api_key: str):
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(200).execute()
    return [_full(l) for l in (result.data or [])]


@router.get("/incidents")
async def get_incidents(api_key: str):
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(200).execute()
    logs = result.data or []
    # Flag = high/medium risk OR policy violations OR explicit flagged=True
    incidents = [
        l for l in logs
        if l.get("flagged")
        or l.get("risk_level") in ("high", "medium", "critical")
        or (l.get("policy_violations") or [])
        or (l.get("compliance_violations") or [])
    ]
    return [_full(l) for l in incidents]


@router.get("/drift")
async def get_drift(api_key: str):
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(500).execute()
    logs = result.data or []
    agent_name = logs[0].get("agent_id", "") if logs else ""

    drift = detect_drift(logs, agent_name=agent_name)

    # Optionally enrich with Groq if key present and findings exist
    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key and drift.get("status") == "drift_detected" and drift.get("groq_context"):
        try:
            from core_ai.groq_reasoning import analyze_drift_with_groq
            drift["ai_narrative"] = analyze_drift_with_groq(drift["groq_context"], api_key=groq_key)
        except Exception:
            pass

    drift.pop("groq_context", None)
    return drift


@router.get("/structuring")
async def get_structuring(api_key: str):
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(500).execute()
    logs = result.data or []

    result_data = detect_structuring(logs)

    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key and result_data.get("groq_contexts"):
        try:
            from core_ai.groq_reasoning import analyze_structuring_with_groq
            result_data["ai_narratives"] = analyze_structuring_with_groq(
                result_data["groq_contexts"], api_key=groq_key
            )
        except Exception:
            pass

    result_data.pop("groq_contexts", None)
    return result_data


@router.get("/structural-anomalies")
async def get_structural_anomalies(api_key: str):
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(200).execute()
    logs = result.data or []
    
    anomalies = []
    for l in logs:
        # Check if the flag_reason contains "STRUCTURAL_ISSUE"
        flag_reason = str(l.get("flag_reason") or l.get("reasoning") or "").upper()
        if "STRUCTURAL_ISSUE" in flag_reason or "LAZY" in flag_reason or "MISSING" in flag_reason:
            anomalies.append(_full(l))
    
    return {
        "anomalies": anomalies,
        "count": len(anomalies),
        "status": "issues_detected" if anomalies else "clean"
    }



@router.get("/report")
async def get_report(api_key: str, session_id: str = None):
    query = supabase.table("audit_logs").select("*").eq("api_key", api_key)
    if session_id:
        query = query.eq("session_id", session_id)
    logs = query.order("created_at", desc=True).execute().data
    if not logs:
        return {"message": "No data yet for this api_key"}
    daos = []
    for l in logs:
        dao = DAO(
            decision_id=l.get("decision_id") or "",
            session_id=l.get("session_id") or "",
            timestamp=str(l.get("created_at", "")),
            agent_name=l.get("agent_id") or "",
            action_type=l.get("action_type") or "unknown",
            risk_level=l.get("risk_level") or "low",
            flag_reason=(l.get("policy_violations") or [None])[0] if l.get("policy_violations") else None,
            reasoning=l.get("reasoning"),
            compliance_tags=l.get("compliance_tags") or [],
            compliance_violations=l.get("compliance_violations") or [],
            input=_parse(l.get("inputs")),
            output=_parse(l.get("output")),
            ai_explanation=l.get("ai_explanation"),
            ai_recommended_action=l.get("ai_recommended_action"),
            ai_escalate_to_human=l.get("ai_escalate_to_human", False),
            ai_regulatory_refs=l.get("ai_regulatory_refs") or [],
            ai_compliance_status=l.get("ai_compliance_status"),
        )
        daos.append(dao)
    sid = session_id or (logs[0].get("session_id") or "all")
    return generate_report(sid, daos)


@router.get("/verify-chain")
async def verify_audit_chain(api_key: str):
    return verify_chain(api_key)


from core_ai.nl_query import query_logs

@router.post("/query")
async def nl_query(data: dict):
    api_key = data.get("api_key", "")
    question = data.get("question", "")
    if not api_key:
        return {"answer": "api_key required", "logs_analyzed": 0}
    result = supabase.table("audit_logs")\
        .select("*").eq("api_key", api_key)\
        .order("created_at", desc=True).limit(100).execute()
    logs = result.data or []
    answer = query_logs(question, logs)
    return {"answer": answer, "logs_analyzed": len(logs)}
