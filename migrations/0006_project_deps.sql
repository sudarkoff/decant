-- Dependency summary of each project's default branch (sent by the action's main sync): one row per project.
-- json is an array of {eco, name, version, direct, via}; the dashboard uses it to split direct from transitive.
CREATE TABLE project_deps (project_id TEXT PRIMARY KEY REFERENCES projects(id), sha TEXT NOT NULL, synced_at TEXT NOT NULL, json TEXT NOT NULL);
