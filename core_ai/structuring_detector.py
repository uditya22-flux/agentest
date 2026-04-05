"""
Cross-session Structuring Detection — v2
Catches agents repeatedly approving amounts just below ₹50,000 threshold
— a classic money laundering pattern RBI specifically watches for.

v2 adds:
  - Velocity window detection (burst of approvals within N minutes)
  - Multi-session aggregation (same beneficial owner across sessions)
  - Groq-ready context block per finding
  - Severity scoring with STR trigger assessment
"""
from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import ast


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _parse_ts(ts_str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts_str).replace("Z", "").strip())
    except Exception:
        return None


def _extract_amount(log: dict) -> float:
    try:
        inp = log.get("inputs") or log.get("input") or {}
        if isinstance(inp, str):
            inp = ast.literal_eval(inp)
        return float(inp.get("amount", 0) if isinstance(inp, dict) else 0)
    except Exception:
        return 0.0


def _extract_owner(log: dict) -> str:
    """Try to get a beneficial owner / customer identifier from inputs."""
    try:
        inp = log.get("inputs") or log.get("input") or {}
        if isinstance(inp, str):
            inp = ast.literal_eval(inp)
        if isinstance(inp, dict):
            return (
                inp.get("customer_id")
                or inp.get("user_id")
                or inp.get("beneficiary_id")
                or log.get("user_id")
                or ""
            )
    except Exception:
        pass
    return ""


def _action(log: dict) -> str:
    return (log.get("action_type") or log.get("action") or "unknown").lower()


def _get_approvals(logs: List[dict]) -> List[dict]:
    result = []
    for log in logs:
        try:
            amount = _extract_amount(log)
            if _action(log) == "approve" and amount > 0:
                result.append({
                    "amount": amount,
                    "session_id": log.get("session_id", ""),
                    "decision_id": log.get("decision_id", ""),
                    "created_at": log.get("created_at", ""),
                    "dt": _parse_ts(log.get("created_at", "")),
                    "owner": _extract_owner(log),
                    "agent_name": log.get("agent_name") or log.get("agent_id") or "",
                })
        except Exception:
            continue
    return result


def _groq_context_for_finding(finding: dict, approvals: List[dict]) -> str:
    """Builds a focused Groq prompt snippet for this specific structuring finding."""
    lines = [
        f"STRUCTURING FINDING: {finding['pattern'].upper()}",
        f"Severity: {finding['severity'].upper()}",
        f"Description: {finding['description']}",
        f"RBI Reference: {finding['rbi_reference']}",
        "",
        "Flagged transaction samples:",
    ]
    flagged_ids = set(finding.get("flagged_decisions", []))
    samples = [a for a in approvals if a["decision_id"] in flagged_ids][:5]
    for s in samples:
        lines.append(
            f"  - decision_id={s['decision_id']} | amount=₹{s['amount']} | "
            f"session={s['session_id']} | at={s['created_at']}"
        )
    lines += [
        "",
        "ANALYSIS INSTRUCTIONS:",
        "1. Does this pattern constitute structuring under PMLA 2002?",
        "2. Is the amount split across sessions or a single session?",
        "3. Should an STR be filed? If yes, by when and to which authority?",
        "4. What additional data should the CCO request from the agent operator?",
        "5. Are there any mitigating factors (e.g., KYC verified, known business purpose)?",
        "6. Assign a money laundering risk rating: low | medium | high | critical.",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# DETECTION PATTERNS
# ─────────────────────────────────────────────────────────────

def _pattern_near_threshold(approvals: List[dict]) -> Optional[dict]:
    """Pattern 1: Multiple approvals ₹40,000–₹49,999 (just under RBI reporting threshold)."""
    near = [a for a in approvals if 40000 <= a["amount"] < 50000]
    if len(near) >= 3:
        total = sum(a["amount"] for a in near)
        sessions = len(set(a["session_id"] for a in near))
        return {
            "pattern": "threshold_structuring",
            "severity": "high",
            "str_trigger": True,
            "description": (
                f"{len(near)} approvals between ₹40,000–₹49,999 across {sessions} session(s). "
                f"Cumulative total: ₹{total:,.0f}. Classic threshold-avoidance structuring."
            ),
            "rbi_reference": (
                "RBI KYC Master Direction (Aug 2025) — suspicious transaction reporting; "
                "PMLA 2002 Section 12 — STR mandatory within 7 days of suspicion."
            ),
            "flagged_decisions": [a["decision_id"] for a in near],
            "groq_context": _groq_context_for_finding(
                {"pattern": "threshold_structuring", "severity": "high",
                 "description": f"{len(near)} near-threshold approvals totaling ₹{total:,.0f}.",
                 "rbi_reference": "RBI KYC Master Direction + PMLA 2002",
                 "flagged_decisions": [a["decision_id"] for a in near]},
                approvals
            ),
        }
    return None


def _pattern_repeated_identical(approvals: List[dict]) -> Optional[dict]:
    """Pattern 2: Exact same amount approved 5+ times — automated structuring signal."""
    amount_counts = Counter(a["amount"] for a in approvals)
    for amount, count in amount_counts.most_common():
        if count >= 5:
            hits = [a for a in approvals if a["amount"] == amount]
            sessions = len(set(a["session_id"] for a in hits))
            total = amount * count
            finding = {
                "pattern": "repeated_identical_amount",
                "severity": "high" if amount >= 10000 else "medium",
                "str_trigger": count >= 8 or (amount >= 10000 and count >= 5),
                "description": (
                    f"Exact amount ₹{amount:,.0f} approved {count} times across {sessions} session(s). "
                    f"Total value: ₹{total:,.0f}. Possible automated or scripted structuring."
                ),
                "rbi_reference": (
                    "RBI FREE-AI Framework — unusual automated pattern; "
                    "PMLA 2002 — repeated identical transactions are a red flag indicator."
                ),
                "flagged_decisions": [a["decision_id"] for a in hits],
            }
            finding["groq_context"] = _groq_context_for_finding(finding, approvals)
            return finding
    return None


def _pattern_velocity_burst(approvals: List[dict], window_minutes: int = 30) -> Optional[dict]:
    """
    Pattern 3 (NEW): 5+ approvals within a short time window across sessions.
    Suggests a coordinated burst of transactions to avoid detection.
    """
    dated = [a for a in approvals if a["dt"] is not None]
    dated.sort(key=lambda x: x["dt"])
    window = timedelta(minutes=window_minutes)

    for i, anchor in enumerate(dated):
        burst = [a for a in dated[i:] if a["dt"] - anchor["dt"] <= window]
        if len(burst) >= 5:
            total = sum(a["amount"] for a in burst)
            sessions = len(set(a["session_id"] for a in burst))
            finding = {
                "pattern": "velocity_burst",
                "severity": "high",
                "str_trigger": total >= 100000,
                "description": (
                    f"{len(burst)} approvals within {window_minutes} minutes "
                    f"(from {anchor['created_at']} onward). "
                    f"Total: ₹{total:,.0f} across {sessions} session(s). "
                    f"Velocity burst pattern — possible coordinated structuring."
                ),
                "rbi_reference": (
                    "PMLA 2002 — rapid succession of transactions is a typology indicator; "
                    "RBI FREE-AI Sutra 7 (Safety) — agent must not facilitate burst transaction exploitation."
                ),
                "flagged_decisions": [a["decision_id"] for a in burst],
            }
            finding["groq_context"] = _groq_context_for_finding(finding, approvals)
            return finding
    return None


def _pattern_cross_owner_aggregation(approvals: List[dict]) -> Optional[dict]:
    """
    Pattern 4 (NEW): Multiple owners/customers all just under threshold —
    possible smurfing (distributing transactions across people).
    """
    near = [a for a in approvals if 40000 <= a["amount"] < 50000]
    owners = [a["owner"] for a in near if a["owner"]]
    unique_owners = set(owners)

    if len(near) >= 4 and len(unique_owners) >= 2:
        total = sum(a["amount"] for a in near)
        finding = {
            "pattern": "smurfing_cross_owner",
            "severity": "high",
            "str_trigger": True,
            "description": (
                f"{len(near)} near-threshold approvals across {len(unique_owners)} distinct customer IDs. "
                f"Total: ₹{total:,.0f}. Possible smurfing — distribution across multiple beneficiaries "
                f"to avoid single-transaction reporting."
            ),
            "rbi_reference": (
                "PMLA 2002 — smurfing is a known layering typology; "
                "RBI KYC Master Direction — beneficial ownership tracing required for suspicious clusters."
            ),
            "flagged_decisions": [a["decision_id"] for a in near],
            "unique_owners": list(unique_owners),
        }
        finding["groq_context"] = _groq_context_for_finding(finding, approvals)
        return finding
    return None


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def detect_structuring(recent_logs: List[Dict[str, Any]]) -> dict:
    """
    Runs all structuring detection patterns on the provided logs.
    Returns a result dict:
      - findings: list of all patterns detected (not just first match)
      - str_required: bool — whether any finding mandates an STR filing
      - groq_contexts: list of per-finding Groq analysis blocks
      - summary: plain-text summary for the report
    """
    approvals = _get_approvals(recent_logs)

    if not approvals:
        return {
            "findings": [],
            "str_required": False,
            "summary": "No approval transactions found in provided logs.",
        }

    # Run all patterns — collect ALL matches, not just first
    detectors = [
        _pattern_near_threshold,
        _pattern_repeated_identical,
        _pattern_velocity_burst,
        _pattern_cross_owner_aggregation,
    ]

    findings = []
    for detector in detectors:
        result = detector(approvals)
        if result:
            findings.append(result)

    str_required = any(f.get("str_trigger") for f in findings)
    overall_severity = (
        "critical" if len(findings) >= 3
        else "high" if findings and any(f["severity"] == "high" for f in findings)
        else "medium" if findings
        else "clean"
    )

    summary_lines = [f"Structuring scan over {len(approvals)} approve decisions."]
    if not findings:
        summary_lines.append("No structuring patterns detected.")
    else:
        for f in findings:
            summary_lines.append(f"[{f['severity'].upper()}] {f['pattern']}: {f['description']}")
        if str_required:
            summary_lines.append(
                "ACTION REQUIRED: One or more findings trigger STR filing obligation under PMLA 2002. "
                "File with FIU-IND within 7 days of confirmed suspicion."
            )

    return {
        "findings": findings,
        "finding_count": len(findings),
        "str_required": str_required,
        "overall_severity": overall_severity,
        "groq_contexts": [f["groq_context"] for f in findings if "groq_context" in f],
        "summary": " | ".join(summary_lines),
    }
