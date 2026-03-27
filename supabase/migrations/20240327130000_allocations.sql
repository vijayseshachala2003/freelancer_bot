-- Who may verify: email + soul_id must match; projects drives Discord roles (bot_verifier.py)
CREATE TABLE IF NOT EXISTS allocations (
    soul_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    discord_email TEXT,
    full_name TEXT,
    projects TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_allocations_email ON allocations (email);
