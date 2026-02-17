-- Phase 3: Add observed_roots to sessions table
ALTER TABLE sessions ADD COLUMN observed_roots_json TEXT DEFAULT '[]';
