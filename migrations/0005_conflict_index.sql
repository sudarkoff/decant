-- Needs-attention lists publish-time conflicts on every dashboard load; keep that a probe of the few conflicted rows.
CREATE INDEX idx_versions_conflict ON versions (eco, name, version) WHERE conflict = 1;
