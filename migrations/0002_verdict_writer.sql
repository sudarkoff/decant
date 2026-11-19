-- Project whose CI token wrote the current verdict row (NULL for rows written before this migration).
ALTER TABLE verdicts ADD COLUMN project_id TEXT;
