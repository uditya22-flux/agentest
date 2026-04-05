"""
GET /report/html  — Returns a fully formatted, printable HTML compliance report.
Ready to hand to an RBI examiner. Print or save as PDF from browser.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from database import supabase
from core_ai.dao import DAO
from core_ai.report_generator import generate_report
from datetime import datetime, timezone
import ast, json

router = APIRouter()

def _parse(raw) -> dict:
    if isinstance(raw, dict): return raw
    try: return ast.literal_eval(str(raw))
    except: return {}

def _score_color(score: int) -> str:
    if score >= 80: return "#00b894"
    if score >= 60: return "#f0a500"
    return "#e53e3e"

def _verdict_color(verdict: str) -> str:
    v = verdict.upper()
    if "NON" in v: return "#e53e3e"
    if "PARTIAL" in v: return "#f0a500"
    if "MOSTLY" in v: return "#f0a500"
    return "#00b894"

def _risk_badge(level: str) -> str:
    colors = {
        "high": ("e53e3e", "fff5f5"),
        "critical": ("e53e3e", "fff5f5"),
        "medium": ("d97706", "fffbeb"),
        "low": ("00b894", "e6f9f5"),
    }
    c, bg = colors.get((level or "low").lower(), ("888", "f5f5f5"))
    return f'<span style="background:#{bg};color:#{c};border:1px solid #{c}33;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;font-family:monospace">{level.upper()}</span>'

def _fmt_ts(ts) -> str:
    if not ts: return "—"
    try:
        s = str(ts).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.strftime("%d %b %Y, %H:%M UTC")
    except: return str(ts)

def build_html(report: dict, api_key: str) -> str:
    ss = report.get("session_summary", {})
    rb = report.get("rbi_response_block", {})
    total = ss.get("total_decisions", 0)
    flagged = ss.get("flagged", 0)
    clean = ss.get("clean", 0)
    score = round((clean / max(total, 1)) * 100)
    verdict = report.get("verdict", "")
    risk_bd = ss.get("risk_breakdown", {})
    flagged_decisions = report.get("flagged_decisions", [])
    compliance_cov = report.get("compliance_coverage", {})
    violation_sum = report.get("violation_summary", {})

    sc = _score_color(score)
    vc = _verdict_color(verdict)
    report_id = report.get("report_id", "—")
    agent_name = report.get("agent_name", "—")
    gen_at = _fmt_ts(report.get("generated_at", ""))

    # Build flagged decisions rows
    flagged_rows = ""
    for i, d in enumerate(flagged_decisions):
        flag = d.get("flag_reason") or "—"
        inp = d.get("input") or {}
        if isinstance(inp, str):
            try: inp = ast.literal_eval(inp)
            except: inp = {}
        flagged_rows += f"""
        <tr style="background:{'#fff5f5' if i%2==0 else '#fff'}">
          <td style="padding:10px 12px;font-family:monospace;font-size:11px;color:#888">{str(d.get('decision_id','—'))[:16]}…</td>
          <td style="padding:10px 12px;font-size:12px">{_fmt_ts(d.get('timestamp'))}</td>
          <td style="padding:10px 12px">{_risk_badge(d.get('risk_level','low'))}</td>
          <td style="padding:10px 12px;font-family:monospace;font-size:11px">{d.get('action_type','—')}</td>
          <td style="padding:10px 12px;font-size:11px;color:#555;max-width:300px">{flag[:120] if flag else '—'}</td>
        </tr>"""

    # Build compliance coverage rows
    cov_rows = ""
    for clause, val in compliance_cov.items():
        try:
            parts = str(val).replace(" decisions","").split("/")
            pct = round(int(parts[0]) / int(parts[1]) * 100)
        except: pct = 0
        bar_color = "#00b894" if pct==100 else "#f0a500" if pct>0 else "#e53e3e"
        status = "PASS" if pct==100 else ("PARTIAL" if pct>0 else "FAIL")
        status_color = "#00b894" if pct==100 else "#d97706" if pct>0 else "#e53e3e"
        short = clause.split("—")[0].strip() if "—" in clause else clause[:60]
        cov_rows += f"""
        <tr>
          <td style="padding:10px 12px;font-size:12px">{short}</td>
          <td style="padding:10px 12px;font-size:12px;text-align:center">{val}</td>
          <td style="padding:10px 12px">
            <div style="background:#eee;border-radius:4px;height:8px;width:100px">
              <div style="background:{bar_color};width:{pct}%;height:8px;border-radius:4px"></div>
            </div>
          </td>
          <td style="padding:10px 12px;font-size:11px;font-weight:600;color:{status_color}">{status}</td>
        </tr>"""

    # Build violations rows
    viol_rows = ""
    for desc, count in sorted(violation_sum.items(), key=lambda x: -x[1]):
        sev_color = "#e53e3e" if count >= 3 else "#d97706" if count >= 2 else "#555"
        viol_rows += f"""
        <tr>
          <td style="padding:10px 12px;font-size:12px;color:#333">{desc[:100]}</td>
          <td style="padding:10px 12px;text-align:center;font-family:monospace;font-weight:600;color:{sev_color}">{count}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AgentBridge Compliance Report — {report_id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;font-size:13px;color:#1a1a2e;background:#f8f9fc;line-height:1.6}}
  .page{{max-width:900px;margin:0 auto;padding:40px 32px;background:#fff}}
  @media print{{body{{background:#fff}}.no-print{{display:none}}@page{{margin:20mm}}.page{{padding:0}}}}

  /* HEADER */
  .report-header{{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:3px solid #0f1420;margin-bottom:32px}}
  .brand{{font-size:22px;font-weight:700;color:#0f1420;letter-spacing:-0.5px}}
  .brand span{{color:#00b894}}
  .report-meta{{text-align:right;font-size:11px;color:#666}}
  .report-meta strong{{display:block;font-size:13px;color:#0f1420;margin-bottom:4px}}

  /* SECTION */
  .section{{margin-bottom:32px}}
  .section-title{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#888;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #eee}}

  /* SCORE CARDS */
  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}}
  .card{{background:#f8f9fc;border:1px solid #e8ecf2;border-radius:10px;padding:16px}}
  .card-label{{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#888;margin-bottom:6px}}
  .card-val{{font-size:26px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}}
  .card-sub{{font-size:11px;color:#888;margin-top:4px}}

  /* VERDICT BANNER */
  .verdict-banner{{border-radius:10px;padding:20px 24px;margin-bottom:32px;display:flex;align-items:center;justify-content:space-between}}

  /* TABLE */
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  thead th{{background:#0f1420;color:#fff;padding:10px 12px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.6px}}
  tbody tr:hover{{background:#f8f9fc}}
  tbody td{{border-bottom:1px solid #f0f0f0}}

  /* RBI BLOCK */
  .rbi-block{{background:#f0faf7;border:1px solid #00b89433;border-radius:10px;padding:20px 24px}}
  .rbi-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #00b89422;font-size:12px}}
  .rbi-row:last-child{{border-bottom:none}}
  .rbi-key{{color:#555;font-weight:500}}
  .rbi-val{{color:#0f1420;font-weight:600;font-family:'JetBrains Mono',monospace;font-size:11px}}

  /* PRINT BTN */
  .print-btn{{position:fixed;bottom:24px;right:24px;background:#0f1420;color:#fff;border:none;border-radius:8px;padding:12px 20px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,0.2);display:flex;align-items:center;gap:8px}}
  .print-btn:hover{{background:#1a2035}}

  /* WATERMARK */
  .watermark{{text-align:center;font-size:10px;color:#bbb;margin-top:40px;padding-top:20px;border-top:1px solid #eee}}
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="report-header">
    <div>
      <div class="brand">Agent<span>Bridge</span></div>
      <div style="font-size:12px;color:#666;margin-top:4px">AI Compliance Audit Report</div>
      <div style="font-size:11px;color:#999;margin-top:2px">RBI FREE-AI Framework (August 2025)</div>
    </div>
    <div class="report-meta">
      <strong>{report_id}</strong>
      Generated: {gen_at}<br>
      Agent: {agent_name}<br>
      API Key: {api_key[:8]}…
    </div>
  </div>

  <!-- SCORE CARDS -->
  <div class="cards">
    <div class="card">
      <div class="card-label">Compliance Score</div>
      <div class="card-val" style="color:{sc}">{score}%</div>
      <div class="card-sub">of decisions clean</div>
    </div>
    <div class="card">
      <div class="card-label">Total Decisions</div>
      <div class="card-val">{total}</div>
      <div class="card-sub">audited this session</div>
    </div>
    <div class="card">
      <div class="card-label">Flagged</div>
      <div class="card-val" style="color:#e53e3e">{flagged}</div>
      <div class="card-sub">require review</div>
    </div>
    <div class="card">
      <div class="card-label">Risk Breakdown</div>
      <div style="display:flex;gap:8px;margin-top:4px;flex-wrap:wrap">
        {f'<span style="font-size:11px;font-weight:600;color:#e53e3e">{risk_bd.get("high",0)} high</span>' if risk_bd.get("high",0) else ""}
        {f'<span style="font-size:11px;font-weight:600;color:#d97706">{risk_bd.get("medium",0)} med</span>' if risk_bd.get("medium",0) else ""}
        {f'<span style="font-size:11px;font-weight:600;color:#00b894">{risk_bd.get("low",0)} low</span>' if risk_bd.get("low",0) else ""}
      </div>
    </div>
  </div>

  <!-- VERDICT -->
  <div class="verdict-banner" style="background:{'#fff5f5' if 'NON' in verdict.upper() else '#fffbeb' if 'PARTIAL' in verdict.upper() or 'MOSTLY' in verdict.upper() else '#f0faf7'};border:1px solid {'#e53e3e44' if 'NON' in verdict.upper() else '#f0a50044' if 'PARTIAL' in verdict.upper() else '#00b89444'}">
    <div>
      <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#888;margin-bottom:6px">Compliance Verdict</div>
      <div style="font-size:16px;font-weight:700;color:{vc}">{verdict}</div>
    </div>
    <div style="font-size:11px;color:#666;text-align:right;max-width:280px;line-height:1.5">
      Prepared by AgentBridge Audit System<br>
      Framework: RBI FREE-AI (August 2025)
    </div>
  </div>

  <!-- FLAGGED DECISIONS -->
  {f'''
  <div class="section">
    <div class="section-title">Flagged Decisions ({len(flagged_decisions)})</div>
    <table>
      <thead>
        <tr>
          <th>Decision ID</th>
          <th>Timestamp</th>
          <th>Risk</th>
          <th>Action Type</th>
          <th>Flag Reason</th>
        </tr>
      </thead>
      <tbody>{flagged_rows}</tbody>
    </table>
  </div>
  ''' if flagged_decisions else '<div class="section"><div class="section-title">Flagged Decisions</div><div style="padding:20px;text-align:center;color:#00b894;font-size:12px;background:#f0faf7;border-radius:8px;border:1px solid #00b89433">✓ No flagged decisions — all decisions passed compliance checks</div></div>'}

  <!-- COMPLIANCE COVERAGE -->
  {f'''
  <div class="section">
    <div class="section-title">RBI FREE-AI Clause Coverage</div>
    <table>
      <thead>
        <tr>
          <th>Clause</th>
          <th style="text-align:center">Coverage</th>
          <th>Progress</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>{cov_rows}</tbody>
    </table>
  </div>
  ''' if compliance_cov else ''}

  <!-- VIOLATIONS -->
  {f'''
  <div class="section">
    <div class="section-title">Violation Summary</div>
    <table>
      <thead>
        <tr>
          <th>Violation</th>
          <th style="text-align:center;width:80px">Count</th>
        </tr>
      </thead>
      <tbody>{viol_rows}</tbody>
    </table>
  </div>
  ''' if violation_sum else ''}

  <!-- RBI RESPONSE BLOCK -->
  <div class="section">
    <div class="section-title">RBI Examination Response Block</div>
    <div class="rbi-block">
      <div class="rbi-row"><span class="rbi-key">Prepared by</span><span class="rbi-val">{rb.get("prepared_by","AgentBridge Audit System")}</span></div>
      <div class="rbi-row"><span class="rbi-key">Framework</span><span class="rbi-val">{rb.get("framework","RBI FREE-AI Framework (August 2025)")}</span></div>
      <div class="rbi-row"><span class="rbi-key">Session covered</span><span class="rbi-val">{rb.get("session_covered","—")}</span></div>
      <div class="rbi-row"><span class="rbi-key">Total decisions audited</span><span class="rbi-val">{rb.get("total_agent_decisions_audited", total)}</span></div>
      <div class="rbi-row"><span class="rbi-key">High risk decisions</span><span class="rbi-val" style="color:#e53e3e">{rb.get("high_risk_decisions", risk_bd.get("high",0))}</span></div>
      <div class="rbi-row"><span class="rbi-key">Compliance verdict</span><span class="rbi-val" style="color:{vc}">{rb.get("compliance_verdict", verdict)}</span></div>
      <div class="rbi-row"><span class="rbi-key">Report generated</span><span class="rbi-val">{_fmt_ts(rb.get("generated_at", report.get("generated_at","")))}</span></div>
    </div>
    <div style="margin-top:12px;font-size:11px;color:#888;line-height:1.6;padding:12px;background:#f8f9fc;border-radius:8px;border:1px solid #eee">
      {rb.get("note","This report was auto-generated by AgentBridge. All decisions are logged, timestamped, and mapped against the RBI FREE-AI Framework.")}
    </div>
  </div>

  <!-- WATERMARK -->
  <div class="watermark">
    AgentBridge Compliance Gateway v5 &nbsp;·&nbsp; Report ID: {report_id} &nbsp;·&nbsp; {gen_at}<br>
    This document is system-generated and tamper-evident. For regulatory use.
  </div>

</div>

<!-- PRINT BUTTON -->
<button class="print-btn no-print" onclick="window.print()">🖨 Print / Save as PDF</button>

</body>
</html>"""


@router.get("/report/html", response_class=HTMLResponse)
async def get_report_html(api_key: str, session_id: str = None):
    """Returns a fully formatted, printable HTML compliance report."""
    query = supabase.table("audit_logs").select("*").eq("api_key", api_key)
    if session_id:
        query = query.eq("session_id", session_id)
    logs = query.order("created_at", desc=True).execute().data

    if not logs:
        return HTMLResponse("""
        <html><body style="font-family:sans-serif;padding:40px;color:#555">
        <h2>No data found</h2><p>No audit logs found for this API key.</p>
        </body></html>""")

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
    raw_report = generate_report(sid, daos)
    html = build_html(raw_report, api_key)
    return HTMLResponse(content=html)
