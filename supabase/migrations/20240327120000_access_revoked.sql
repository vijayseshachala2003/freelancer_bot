-- Add access_revoked for manual / admin access removal (bot_verifier.py)
ALTER TABLE discord_user_verification
ADD COLUMN IF NOT EXISTS access_revoked BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_duv_access_revoked
ON discord_user_verification (guild_id, access_revoked)
WHERE access_revoked = TRUE;
