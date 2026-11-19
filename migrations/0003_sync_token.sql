-- Widen tokens.kind to include 'sync'. SQLite cannot alter a CHECK in place, so rebuild the table.
CREATE TABLE tokens_new (hash TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), kind TEXT NOT NULL CHECK (kind IN ('read','ci','sync')), created_at TEXT NOT NULL);
INSERT INTO tokens_new (hash, project_id, kind, created_at) SELECT hash, project_id, kind, created_at FROM tokens;
DROP TABLE tokens;
ALTER TABLE tokens_new RENAME TO tokens;
