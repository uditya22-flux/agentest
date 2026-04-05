import os
from core_ai.dao import DAO
from core_ai.parser import parse_to_dao
from core_ai.anomaly import check_anomalies
from core_ai.compliance import map_compliance
from core_ai.ai_analyser import analyze
from typing import Any, Dict

def process(raw_log: Dict[str, Any]) -> DAO:
    """
    Full pipeline — Groq only.
    Step 1: Parse
    Step 2: Rule-based anomaly detection
    Step 3: RBI clause compliance mapping
    Step 4: Groq AI analysis (skipped gracefully if GROQ_API_KEY not set)
    """
    dao = parse_to_dao(raw_log)
    dao = check_anomalies(dao)
    dao = map_compliance(dao)

    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key:
        dao = analyze(dao, groq_key)
    else:
        dao.ai_explanation = "AI analysis disabled — set GROQ_API_KEY"
        dao.ai_compliance_status = "unknown"
        dao.ai_risk_level = dao.risk_level

    return dao
