-- Docker base images in use on each project's default branch, sent by the action's main sync: one row per
-- image digest (name is the fully qualified repository, e.g. docker.io/library/node). files: JSON array of the
-- Dockerfiles that use it. The Needs-attention list treats these as installed, the way serve_log rows are.
-- A digest's cooldown clock is versions.first_seen (eco 'docker'), never the image's own metadata.
CREATE TABLE project_images (project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL, digest TEXT NOT NULL, files TEXT NOT NULL, synced_at TEXT NOT NULL, PRIMARY KEY (project_id, name, digest));
-- First-seen of image digests decant could not verify in a public registry (private or unsupported registry):
-- a clock for this project only, so one project's CI can never start the shared clock for a digest nobody has
-- seen published. Digests verified by the Worker itself go in versions (eco 'docker'), shared by every project.
CREATE TABLE project_image_seen (project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL, digest TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY (project_id, name, digest));
