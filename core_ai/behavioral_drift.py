"""
Behavioral Drift Detection — v3
Compares agent's LAST 5 decisions vs PREVIOUS 5 decisions.
Also extracts the decision-making pattern from recent logs.
Works with any volume of data — no week-minimum required.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import Counter
import statistics


def _parse_ts(ts_str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts_str).replace("Z", "").strip())
    except Exception:
        return None


def _action(log: dict) -> str:
    return (log.get("action_type") or log.get("action") or "unknown").lower()


def _amount(log: dict) -> float:
    try:
        inp = log.get("inputs") or log.get("input") or {}
        if isinstance(inp, str):
            import ast; inp = ast.literal_eval(inp)
        return float(inp.get("amount", 0) if isinstance(inp, dict) else 0)
    except Exception:
        return 0.0


def _confidence(log: dict) -> float:
    try:
        return float(log.get("confidence", 1.0))
    except Exception:
        return 1.0


def _has_reasoning(log: dict) -> bool:
    r = log.get("reasoning") or ""
    stripped = str(r).strip()
    return bool(stripped) and stripped.lower() not in ("submitted via agentbridge ui", "none", "null", "")


def _kyc(log: dict) -> bool:
    try:
        inp = log.get("inputs") or log.get("input") or {}
        if isinstance(inp, str):
            import ast; inp = ast.literal_eval(inp)
        v = inp.get("kyc_verified") or inp.get("kyc") if isinstance(inp, dict) else None
        return str(v).lower() in ("true", "1", "yes")
    except Exception:
        return False


def _risk(log: dict) -> str:
    return (log.get("risk_level") or "low").lower()


def _compute_stats(logs: List[dict]) -> Dict[str, Any]:
    if not logs:
        return {}
    total = len(logs)
    actions = [_action(l) for l in logs]
    action_counts = Counter(actions)
    amounts = [_amount(l) for l in logs if _amount(l) > 0]
    confidences = [_confidence(l) for l in logs]
    approved = action_counts.get("approve", 0)
    flagged = sum(1 for l in logs if _risk(l) in ("high", "medium", "critical") or l.get("flagged"))
    missing_reasoning = sum(1 for l in logs if not _has_reasoning(l))
    kyc_missing_on_approve = sum(1 for l in logs if _action(l) == "approve" and not _kyc(l))
    near_threshold = sum(1 for a in amounts if 40000 <= a < 50000)
    latencies = [float(l.get("latency_ms", 0) or 0) for l in logs if l.get("latency_ms")]

    return {
        "total": total,
        "approval_rate": round(approved / total * 100, 1),
        "flag_rate": round(flagged / total * 100, 1),
        "missing_reasoning_rate": round(missing_reasoning / total * 100, 1),
        "kyc_missing_on_approve": kyc_missing_on_approve,
        "avg_confidence": round(statistics.mean(confidences), 3) if confidences else None,
        "avg_amount": round(statistics.mean(amounts)) if amounts else None,
        "max_amount": round(max(amounts)) if amounts else None,
        "near_threshold_count": near_threshold,
        "avg_latency_ms": round(statistics.mean(latencies)) if latencies else None,
        "action_distribution": dict(action_counts),
        "risk_distribution": dict(Counter(_risk(l) for l in logs)),
    }


def _decision_pattern(logs: List[dict]) -> Dict[str, Any]:
    """
    Analyses what decision pattern the agent is following across the last N logs.
    Returns a human-readable pattern summary.
    """
    if not logs:
        return {"pattern": "no_data", "summary": "No logs available."}

    actions = [_action(l) for l in logs]
    risks = [_risk(l) for l in logs]
    amounts = [_amount(l) for l in logs]
    has_reasoning_flags = [_has_reasoning(l) for l in logs]
    kyc_flags = [_kyc(l) for l in logs]
    confidences = [_confidence(l) for l in logs]

    action_counts = Counter(actions)
    dominant_action = action_counts.most_common(1)[0][0] if actions else "unknown"
    dominant_pct = round(action_counts[dominant_action] / len(actions) * 100, 1)

    # Detect specific patterns
    patterns_detected = []

    # Pattern: Approving without reasoning
    approve_no_reason = sum(
        1 for l in logs if _action(l) == "approve" and not _has_reasoning(l)
    )
    if approve_no_reason > 0:
        patterns_detected.append({
            "name": "approval_without_reasoning",
            "label": "Approving without reasoning",
            "count": approve_no_reason,
            "severity": "high",
            "rbi": "FREE-AI Sutra 6 — Explainability violated",
            "detail": f"{approve_no_reason} of {len(logs)} decisions approved with no reasoning logged."
        })

    # Pattern: Approving without KYC
    approve_no_kyc = sum(
        1 for l in logs if _action(l) == "approve" and not _kyc(l)
    )
    if approve_no_kyc > 0:
        patterns_detected.append({
            "name": "approval_without_kyc",
            "label": "Approving without KYC verification",
            "count": approve_no_kyc,
            "severity": "high",
            "rbi": "RBI KYC Master Direction — KYC mandatory before approval",
            "detail": f"{approve_no_kyc} approvals made without KYC verification in input data."
        })

    # Pattern: Low confidence approvals
    low_conf_approvals = sum(
        1 for l in logs if _action(l) == "approve" and _confidence(l) < 0.75
    )
    if low_conf_approvals > 0:
        patterns_detected.append({
            "name": "low_confidence_approvals",
            "label": "Approving with low confidence",
            "count": low_conf_approvals,
            "severity": "medium",
            "rbi": "FREE-AI Sutra 5 — Accountability: agent unsure but still approving",
            "detail": f"{low_conf_approvals} approvals made with confidence < 0.75."
        })

    # Pattern: High-value approvals
    high_value = [a for a in amounts if a > 50000]
    if high_value:
        patterns_detected.append({
            "name": "high_value_approvals",
            "label": "High-value transaction approvals",
            "count": len(high_value),
            "severity": "high",
            "rbi": "RBI KYC Master Direction — EDD required for high-value transactions",
            "detail": f"{len(high_value)} transaction(s) above ₹50,000 approved. Max: ₹{max(high_value):,.0f}."
        })

    # Pattern: Consistent rejection
    if action_counts.get("reject", 0) >= len(logs) * 0.6:
        patterns_detected.append({
            "name": "consistent_rejection",
            "label": "Predominantly rejecting",
            "count": action_counts["reject"],
            "severity": "medium",
            "rbi": "FREE-AI Sutra 4 — Fairness: high rejection rate may indicate bias",
            "detail": f"{action_counts['reject']} of {len(logs)} decisions are rejections ({round(action_counts['reject']/len(logs)*100,1)}%)."
        })

    # Pattern: Near-threshold clustering
    near = [a for a in amounts if 40000 <= a < 50000]
    if len(near) >= 2:
        patterns_detected.append({
            "name": "near_threshold_clustering",
            "label": "Near-threshold amount clustering",
            "count": len(near),
            "severity": "high",
            "rbi": "PMLA 2002 — Structuring indicator, STR may be required",
            "detail": f"{len(near)} transactions between ₹40,000–₹49,999 detected."
        })

    # Build timeline
    timeline = []
    for i, log in enumerate(reversed(logs)):  # oldest first
        timeline.append({
            "index": i + 1,
            "action": _action(log),
            "risk": _risk(log),
            "amount": _amount(log) or None,
            "confidence": _confidence(log),
            "has_reasoning": _has_reasoning(log),
            "kyc": _kyc(log),
            "decision_id": str(log.get("decision_id") or "")[:12],
            "agent": log.get("agent_id") or log.get("agent_name") or "—",
            "timestamp": str(log.get("created_at") or ""),
            "verdict": log.get("verdict") or "—",
            "flag_reason": log.get("flag_reason") or log.get("reasoning") or "",
        })

    # Overall pattern label
    if len(patterns_detected) == 0:
        overall = "clean"
        summary = f"Agent is operating normally. Dominant action: {dominant_action} ({dominant_pct}%)."
    elif any(p["severity"] == "high" for p in patterns_detected):
        overall = "high_risk_pattern"
        summary = (
            f"Agent shows {len(patterns_detected)} compliance issue(s). "
            f"Dominant action: {dominant_action} ({dominant_pct}%). "
            f"Primary concern: {patterns_detected[0]['label']}."
        )
    else:
        overall = "watch"
        summary = (
            f"Agent shows {len(patterns_detected)} warning(s). "
            f"Dominant action: {dominant_action} ({dominant_pct}%)."
        )

    return {
        "pattern": overall,
        "summary": summary,
        "dominant_action": dominant_action,
        "dominant_action_pct": dominant_pct,
        "action_distribution": dict(action_counts),
        "patterns_detected": patterns_detected,
        "timeline": timeline,
    }


def _find_shifts(recent: dict, previous: dict) -> List[dict]:
    """Compare recent 5 vs previous 5 and return meaningful shifts."""
    shifts = []
    if not recent or not previous:
        return shifts

    def _chk(key, label, unit, threshold, direction="both"):
        r = recent.get(key)
        p = previous.get(key)
        if r is None or p is None:
            return
        delta = round(r - p, 2)
        if direction == "both" and abs(delta) < threshold:
            return
        if direction == "up" and delta < threshold:
            return
        if direction == "down" and delta > -threshold:
            return
        severity = "high" if abs(delta) > threshold * 2 else "medium"
        shifts.append({
            "signal": key,
            "label": label,
            "previous": f"{p}{unit}",
            "recent": f"{r}{unit}",
            "delta": f"{'+' if delta > 0 else ''}{delta}{unit}",
            "severity": severity,
        })

    _chk("approval_rate", "Approval rate", "%", 20)
    _chk("flag_rate", "Flag/incident rate", "%", 15, "up")
    _chk("missing_reasoning_rate", "Missing reasoning", "%", 10, "up")
    _chk("avg_confidence", "Avg confidence", "", 0.10, "down")
    _chk("near_threshold_count", "Near-₹50k transactions", "", 1, "up")
    _chk("kyc_missing_on_approve", "Approvals without KYC", "", 1, "up")
    if recent.get("avg_latency_ms") and previous.get("avg_latency_ms"):
        if recent["avg_latency_ms"] > previous["avg_latency_ms"] * 2:
            shifts.append({
                "signal": "latency_spike",
                "label": "Response latency",
                "previous": f"{previous['avg_latency_ms']}ms",
                "recent": f"{recent['avg_latency_ms']}ms",
                "delta": f"+{recent['avg_latency_ms'] - previous['avg_latency_ms']}ms",
                "severity": "medium",
            })

    return shifts


def detect_drift(logs: List[Dict[str, Any]], agent_name: str = "", window: int = 5) -> dict:
    """
    Compares last `window` logs vs previous `window` logs.
    Also returns full decision pattern analysis of recent logs.
    Default window = 5 (works with minimal data).
    """
    if not logs:
        return {
            "status": "insufficient_data",
            "message": "No logs found for this api_key.",
        }

    # Sort newest first (DB returns desc already, but ensure)
    sorted_logs = sorted(
        [l for l in logs if l.get("created_at")],
        key=lambda x: str(x.get("created_at", "")),
        reverse=True,
    )

    recent_n = sorted_logs[:window]
    previous_n = sorted_logs[window: window * 2]

    recent_stats = _compute_stats(recent_n)
    previous_stats = _compute_stats(previous_n) if previous_n else {}
    shifts = _find_shifts(recent_stats, previous_stats) if previous_n else []
    pattern = _decision_pattern(recent_n)

    overall_severity = (
        "high" if any(s["severity"] == "high" for s in shifts) or pattern["pattern"] == "high_risk_pattern"
        else "medium" if shifts or pattern["pattern"] == "watch"
        else "low"
    )

    has_comparison = bool(previous_n)

    return {
        "status": "drift_detected" if shifts else "stable",
        "overall_severity": overall_severity,
        "window": window,
        "total_logs_analysed": len(sorted_logs),
        "has_comparison": has_comparison,

        # Stats for the two windows
        "this_week": recent_stats,   # kept as 'this_week' so dashboard renders without change
        "last_week": previous_stats,

        # Shift signals between windows
        "findings": shifts,
        "finding_count": len(shifts),

        # NEW: Decision pattern block
        "decision_pattern": pattern,

        # Groq context for AI narrative
        "groq_context": _build_groq_context(recent_stats, previous_stats, shifts, pattern, agent_name, window),
    }


def _build_groq_context(recent, previous, shifts, pattern, agent_name, window) -> str:
    lines = [
        f"AGENT BEHAVIOR ANALYSIS — Agent: {agent_name or 'Unknown'}",
        f"Comparing last {window} decisions vs previous {window} decisions.",
        "",
        f"── RECENT {window} DECISIONS ──────────────────────────",
    ]
    for k, v in recent.items():
        lines.append(f"  {k}: {v}")

    if previous:
        lines += [f"", f"── PREVIOUS {window} DECISIONS ─────────────────────────"]
        for k, v in previous.items():
            lines.append(f"  {k}: {v}")

    lines += ["", "── BEHAVIORAL SHIFTS DETECTED ─────────────────────"]
    if not shifts:
        lines.append("  No significant shifts between windows.")
    else:
        for s in shifts:
            lines.append(f"  [{s['severity'].upper()}] {s['label']}: {s['previous']} → {s['recent']} ({s['delta']})")

    lines += ["", "── DECISION PATTERN ───────────────────────────────"]
    lines.append(f"  Pattern: {pattern['pattern']}")
    lines.append(f"  Summary: {pattern['summary']}")
    for p in pattern.get("patterns_detected", []):
        lines.append(f"  [{p['severity'].upper()}] {p['label']}: {p['detail']} ({p['rbi']})")

    lines += [
        "", "── DECISION TIMELINE (oldest → newest) ────────────",
    ]
    for t in pattern.get("timeline", []):
        lines.append(
            f"  #{t['index']} {t['action'].upper()} | risk={t['risk']} | "
            f"amount=₹{t['amount'] or 0:,.0f} | conf={t['confidence']} | "
            f"kyc={t['kyc']} | reasoning={'yes' if t['has_reasoning'] else 'MISSING'}"
        )

    lines += [
        "", "── GROQ INSTRUCTIONS ──────────────────────────────",
        "  1. What decision-making pattern is this agent exhibiting?",
        "  2. Are any patterns a compliance violation under RBI FREE-AI, KYC Master Direction, or PMLA?",
        "  3. Has behavior changed between the two windows? Is it getting riskier?",
        "  4. What should the CCO do in the next 24 hours?",
        "  5. Rate overall risk: stable | watch | escalate | critical.",
    ]
    return "\n".join(lines)
