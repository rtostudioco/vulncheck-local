-- SENTINEL DESK 1.0 — 001_init.sql
-- SQLite schema mirroring the verified web prototype data model
-- (prisma/schema.prisma). All timestamps stored as UTC ISO-8601 strings.
-- Provenance: every event carries `synthetic` + `source_ref` so an analyst can
-- always trace a detection back to its origin.
--
-- The connection MUST have `PRAGMA foreign_keys = ON` (enforced by storage::open).

PRAGMA foreign_keys = ON;

-- ─── Events ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS events (
  id                 TEXT PRIMARY KEY,           -- uuid v4
  ts                 TEXT NOT NULL,              -- event generation/collection time (UTC ISO)
  channel            TEXT NOT NULL,              -- "Security" | "System" | "PowerShell/Operational" | "TaskScheduler/Operational" | "Sysmon"
  provider           TEXT NOT NULL,              -- e.g. "Microsoft-Windows-Security-Auditing"
  event_id           INTEGER NOT NULL,
  level              TEXT NOT NULL,              -- Information | Warning | Error | Critical
  computer           TEXT NOT NULL,
  record_id          TEXT,                       -- Windows record number inside the channel (provenance)
  user_name          TEXT,                       -- subject / initiating account
  user_sid           TEXT,
  target_user_name   TEXT,
  process_id         INTEGER,
  process_name       TEXT,
  parent_process_id  INTEGER,
  parent_process_name TEXT,
  command_line       TEXT,
  ip_address         TEXT,
  logon_type         INTEGER,
  service_name       TEXT,
  task_name          TEXT,
  summary            TEXT,                       -- denormalized searchable text
  raw                TEXT,                       -- original raw payload (XML) — provenance for reproduction
  synthetic          INTEGER NOT NULL DEFAULT 0, -- 1 when produced by the labeled demo source
  source_ref         TEXT,
  created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts         ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_event_id   ON events (event_id);
CREATE INDEX IF NOT EXISTS idx_events_channel    ON events (channel);
CREATE INDEX IF NOT EXISTS idx_events_computer   ON events (computer);
CREATE INDEX IF NOT EXISTS idx_events_process_id ON events (process_id);

-- ─── Event sources (health of each Windows channel) ────────────────────────

CREATE TABLE IF NOT EXISTS event_sources (
  id               TEXT PRIMARY KEY,
  channel          TEXT NOT NULL UNIQUE,        -- logical channel name (matches rule catalog)
  display_name     TEXT NOT NULL,
  description      TEXT,
  -- active | demo | permission_required | unavailable
  status           TEXT NOT NULL DEFAULT 'unavailable',
  available        INTEGER NOT NULL DEFAULT 0,
  requires_admin   INTEGER NOT NULL DEFAULT 0,
  note             TEXT,                        -- exact reason for degraded status (never silent)
  last_collect_at  TEXT,
  events_collected INTEGER NOT NULL DEFAULT 0
);

-- ─── Detection rules ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS detection_rules (
  id              TEXT PRIMARY KEY,             -- "SD-001"
  name            TEXT NOT NULL,
  description     TEXT NOT NULL,
  version         TEXT NOT NULL DEFAULT '1.0.0',
  author          TEXT NOT NULL DEFAULT 'Sentinel Desk Core Team',
  severity        TEXT NOT NULL,                -- critical | high | medium | low | info
  category        TEXT NOT NULL,
  mitre_id        TEXT,
  mitre_name      TEXT,
  enabled         INTEGER NOT NULL DEFAULT 1,
  -- Portable JSON rule logic (Sigma-inspired) — EXACT same shape as rules/windows.json
  logic           TEXT NOT NULL,
  false_positives TEXT,
  limitations     TEXT,
  evidence_fields TEXT,                          -- JSON array of strings
  created_at      TEXT NOT NULL
);

-- ─── Alerts ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alerts (
  id          TEXT PRIMARY KEY,
  rule_id     TEXT NOT NULL REFERENCES detection_rules (id),
  severity    TEXT NOT NULL,
  title       TEXT NOT NULL,
  summary     TEXT NOT NULL,
  confidence  INTEGER NOT NULL DEFAULT 60,      -- 0..100, rule-defined confidence in this match
  status      TEXT NOT NULL DEFAULT 'open',     -- open | triaged | linked_to_incident | closed_fp
  evidence    TEXT NOT NULL,                    -- JSON: [{ eventId, matched: [{field, value, op}] }]
  mitre_id    TEXT,
  computer    TEXT,
  user_name   TEXT,
  incident_id TEXT REFERENCES incidents (id),
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at  ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id     ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts (severity);

-- Join table: which physical events constitute an alert's evidence
CREATE TABLE IF NOT EXISTS alert_events (
  alert_id TEXT NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
  PRIMARY KEY (alert_id, event_id)
);

-- ─── Incidents (MODULE 05) ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incidents (
  id               TEXT PRIMARY KEY,
  code             TEXT NOT NULL UNIQUE,        -- "INC-0007"
  title            TEXT NOT NULL,
  severity         TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'new', -- new | investigating | monitoring | resolved | false_positive
  hypothesis       TEXT,                        -- explicit NOT-a-confirmation wording
  correlation_meta TEXT,                        -- JSON: { fields: string[], windowSec: number, host: string, inferred: true }
  summary          TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);

CREATE TABLE IF NOT EXISTS incident_notes (
  id          TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  author      TEXT NOT NULL DEFAULT 'analyst',  -- analyst | system | ai
  body        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

-- ─── AI analyst (full auditability; stored only if ever used) ──────────────

CREATE TABLE IF NOT EXISTS ai_analyses (
  id             TEXT PRIMARY KEY,
  incident_id    TEXT REFERENCES incidents (id) ON DELETE CASCADE,
  kind           TEXT NOT NULL,                 -- "incident_summary" | "detection_explain" | "report_draft" | "indicator_context"
  provider       TEXT NOT NULL,
  model          TEXT NOT NULL,
  privacy_mode   TEXT NOT NULL,                 -- "local_only" | "redacted_remote" | "sandbox"
  prompt_version TEXT NOT NULL,
  input_summary  TEXT NOT NULL,                 -- what was sent (post-redaction)
  output         TEXT NOT NULL,
  created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_incident ON ai_analyses (incident_id);

-- ─── Threat intelligence (local indicator store) ───────────────────────────

CREATE TABLE IF NOT EXISTS indicators (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,                     -- hash | ip | domain | url
  value      TEXT NOT NULL UNIQUE,
  verdict    TEXT NOT NULL DEFAULT 'unknown',   -- unknown | benign | suspicious | malicious
  source     TEXT NOT NULL DEFAULT 'local',     -- local | external:user_authorized
  note       TEXT,
  created_at TEXT NOT NULL
);

-- ─── Settings & audit log ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL                            -- JSON
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY,
  actor      TEXT NOT NULL DEFAULT 'local-analyst',
  action     TEXT NOT NULL,                     -- e.g. "settings.update", "incident.status", "data.purge"
  target     TEXT,
  detail     TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log (created_at);
