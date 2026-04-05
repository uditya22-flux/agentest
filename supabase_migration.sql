-- ============================================================
-- AgentBridge v5 Gateway — Supabase Migration
-- Run this in Supabase SQL Editor
-- ============================================================

-- 1. New immutable audit_logs table (replaces logs)
CREATE TABLE IF NOT EXISTS audit_logs (
    id                    UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    created_at            TIMESTAMPTZ DEFAULT NOW(),

    -- Identity
    api_key               TEXT NOT NULL,
    decision_id           TEXT NOT NULL,
    session_id            TEXT,
    agent_id              TEXT,
    user_id               TEXT,
    action_type           TEXT,
    domain                TEXT DEFAULT 'fintech',

    -- Gateway verdict
    verdict               TEXT NOT NULL,   -- allow | review | reject
    risk_score            FLOAT,
    risk_level            TEXT,
    flagged               BOOLEAN DEFAULT FALSE,

    -- Policy + compliance
    policy_violations     JSONB DEFAULT '[]',
    compliance_violations JSONB DEFAULT '[]',
    compliance_tags       JSONB DEFAULT '[]',

    -- Agent data
    inputs                TEXT,
    output                TEXT,
    reasoning             TEXT,
    confidence            FLOAT,
    latency_ms            INT,
    status                TEXT,

    -- AI analysis
    ai_explanation        TEXT,
    ai_recommended_action TEXT,
    ai_compliance_status  TEXT,
    ai_risk_level         TEXT,
    ai_category           TEXT,
    ai_issue_detected     BOOLEAN,
    ai_confidence_score   FLOAT,
    ai_escalate_to_human  BOOLEAN DEFAULT FALSE,
    ai_regulatory_refs    JSONB DEFAULT '[]',

    -- Hash chain (immutability)
    previous_hash         TEXT NOT NULL,
    log_hash              TEXT NOT NULL UNIQUE
);

-- 2. API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    api_key    TEXT NOT NULL UNIQUE,
    name       TEXT,
    active     BOOLEAN DEFAULT TRUE,
    rate_limit INT DEFAULT 60
);

-- 3. Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_api_key ON audit_logs(api_key);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session ON audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_flagged ON audit_logs(flagged) WHERE flagged = TRUE;
CREATE INDEX IF NOT EXISTS idx_audit_logs_verdict ON audit_logs(verdict);
CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(api_key);

-- 4. Disable direct updates/deletes on audit_logs (immutability enforcement)
-- Run as superuser:
-- REVOKE UPDATE, DELETE ON audit_logs FROM authenticated;
-- REVOKE UPDATE, DELETE ON audit_logs FROM anon;

-- 5. Insert a test API key
INSERT INTO api_keys (api_key, name, active)
VALUES ('test123', 'Development Key', TRUE)
ON CONFLICT (api_key) DO NOTHING;
