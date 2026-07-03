ALTER TABLE scheduled_targets ADD COLUMN scope_include TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduled_targets ADD COLUMN scope_exclude TEXT NOT NULL DEFAULT '';
