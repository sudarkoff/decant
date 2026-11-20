-- Needs-attention to-dos.
-- vulns.fixed_versions: JSON array of every "fixed" version OSV lists for the row's package in that advisory
-- (NULL = not known yet: written before this migration, or reused from another package's row of the advisory).
-- The dashboard shows the lowest one above the installed version.
ALTER TABLE vulns ADD COLUMN fixed_versions TEXT;
-- projects.repo: GitHub "owner/name", sent by the action's default-branch deps sync (NULL for older actions).
ALTER TABLE projects ADD COLUMN repo TEXT;
