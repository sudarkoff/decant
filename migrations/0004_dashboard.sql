-- Dashboard: per-day request counts, latest upstream versions, vulnerability cache and alert state.
CREATE TABLE request_counts (project_id TEXT NOT NULL, day TEXT NOT NULL, eco TEXT NOT NULL, kind TEXT NOT NULL, outcome TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (project_id, day, eco, kind, outcome));
CREATE TABLE packages (eco TEXT NOT NULL, name TEXT NOT NULL, latest TEXT NOT NULL, latest_time TEXT, checked_at TEXT NOT NULL, PRIMARY KEY (eco, name));
CREATE TABLE vulns (eco TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, id TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT, published TEXT, checked_at TEXT NOT NULL, PRIMARY KEY (eco, name, version, id));
CREATE TABLE alerts_state (key TEXT PRIMARY KEY, project_id TEXT, first_seen TEXT NOT NULL, resolved_at TEXT);
ALTER TABLE allows ADD COLUMN advisory_published TEXT;
ALTER TABLE allows ADD COLUMN first_synced_at TEXT;
CREATE INDEX idx_serve_log_day ON serve_log (project_id, day);
