"""
routes/gateway_routes.py
Single entry point: POST /decide
This is the ONLY way to submit a decision.
The old /log endpoint is kept for backward compat but now calls gateway.
"""
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from gateway.decision_gateway import process_decision

router = APIRouter()


@router.post("/decide")
async def decide(request: Request):
    """
    MAIN GATEWAY ENDPOINT.
    Submit a decision for compliance enforcement before execution.
    
    Returns:
        200 — allow (decision cleared)
        202 — review (proceed with caution, human review required)
        403 — reject (decision blocked by policy)
        422 — validation failure
    """
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")

    # Inject api_key from header if not in body
    api_key = request.headers.get("X-API-Key") or raw.get("api_key", "")
    raw["api_key"] = api_key

    response_data, status_code = process_decision(raw)
    return JSONResponse(content=response_data, status_code=status_code)


@router.post("/log")
async def legacy_log(request: Request):
    """
    Backward-compatible endpoint for existing SDK.
    Now routes through the full gateway pipeline.
    """
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    api_key = request.headers.get("X-API-Key") or raw.get("api_key", "")
    raw["api_key"] = api_key

    # Map legacy fields to gateway schema
    if "action" in raw and "action_type" not in raw:
        raw["action_type"] = raw.pop("action")
    if "inputs" in raw and "input" not in raw:
        raw["input"] = raw.pop("inputs") if isinstance(raw["inputs"], dict) else {}
    if "agent_name" in raw and "agent_id" not in raw:
        raw["agent_id"] = raw.pop("agent_name")
    if "user_id" not in raw:
        raw["user_id"] = "legacy_sdk_user"
    if "session_id" not in raw:
        raw["session_id"] = "legacy_session"

    # Map nested confidence for legacy clients
    if "confidence" not in raw:
        out = raw.get("output", {})
        if isinstance(out, dict) and "confidence" in out:
            raw["confidence"] = float(out["confidence"])
        else:
            raw["confidence"] = 0.85

    response_data, status_code = process_decision(raw)
    return JSONResponse(content=response_data, status_code=status_code)


@router.get("/logs")
async def get_logs(api_key: str, limit: int = 50, request: Request = None):
    """Retrieve audit logs for a given api_key."""
    from database import supabase
    result = supabase.table("audit_logs")\
        .select("*")\
        .eq("api_key", api_key)\
        .order("created_at", desc=True)\
        .limit(limit)\
        .execute()
    return result.data
