-- Needs-attention to-dos.
-- vulns.fixed_versions: JSON array of every "fixed" version OSV lists for the row's package in that advisory
-- (NULL = not known yet: written before this migration, or reused from another package's row of the advisory).
-- The dashboard shows the lowest one above the installed version.
ALTER TABLE vulns ADD COLUMN fixed_versions TEXT;
-- vulns.details_fetched_at: when the advisory's details were last fetched from OSV. The cron re-fetches advisories
-- with no fixed version yet, oldest first, so a card updates when a fix ships.
ALTER TABLE vulns ADD COLUMN details_fetched_at TEXT;
-- The cron reads stored details by advisory id.
CREATE INDEX IF NOT EXISTS vulns_id ON vulns (id);
-- projects.repo: GitHub "owner/name", sent by the action's default-branch deps sync (NULL for older actions).
ALTER TABLE projects ADD COLUMN repo TEXT;
