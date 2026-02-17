-- Phase 6: Enforcement and safe mode

ALTER TABLE sessions ADD COLUMN enforcement_actions_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN forced_terminated INTEGER NOT NULL DEFAULT 0;

ALTER TABLE events ADD COLUMN enforcement_action INTEGER NOT NULL DEFAULT 0;
