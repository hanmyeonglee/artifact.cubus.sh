ALTER TABLE upload_tokens ADD COLUMN IF NOT EXISTS pending_title TEXT;
ALTER TABLE upload_tokens ADD COLUMN IF NOT EXISTS pending_visibility TEXT;

ALTER TABLE oauth_authorization_codes ADD COLUMN IF NOT EXISTS replayed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_artifacts_status_created ON artifacts (status, created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_family ON oauth_authorization_codes (family_id);
