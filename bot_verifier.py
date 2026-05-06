import os
import re
import json
import asyncio
import logging
import threading
from dataclasses import dataclass, field
from urllib.parse import quote_plus
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import discord
from aiohttp import web
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# Discord Verification Bot
# ------------------------------------------------------------
# Features:
# - Verify-first: managed access roles are removed until verification succeeds; after verify, roles match **tokens in allocations.projects** (aliases in PROJECT_ROLE_ALIASES); only names in MANAGED_ACCESS_ROLE_NAMES are assignable; extras removed on sync
# - Unverified + Unverified role gate channels; DB `status` = VERIFIED | NOT_VERIFIED (no Discord Verified role)
# - New joins: strip managed access roles, gate, **DM** with Verify now + email modal; existing members audited on startup the same way
# - If someone has a managed access role but DB says not verified → strip access, gate, DM notice (compliance audit)
# - Verified users: resync managed access roles from `allocations.projects` (by canonical `email` PK), else from DB assigned_roles snapshot
# - Hard revoke (!revoke_access / access_revoked): gate + strip managed access roles
# - Admins: !kick / !ban — allocations.status REVOKE/BAN (by stored allocation email); !audit_bluebird — members with any managed access role
# - VERIFICATION_EXEMPT_ROLE_NAMES (code): staff skip verify; marked DB exempt; no allocation resync / strip; Verify UI tells them they are exempt
# - On ready: no auto #verify-yourself setup (verification invites are **DM-only**; VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED unused by stubs)
# - Timeout: strip managed access roles + gate; verification state in PostgreSQL / Supabase
#
# Discord Developer Portal (Bot → Privileged Gateway Intents):
#   - Server Members Intent — required (member list, roles, on_member_join).
#   - Message Content Intent — required for prefix commands (!helpme, !kick, !ban, etc.).
#
# Channel permissions (gate model): gated categories/channels must allow invite roles (e.g. BB_Access) and
# explicitly deny Unverified for View Channel (or equivalent), or users will not be blocked despite DB logic.
#
# Gate model (Discord-side):
# - On categories/channels for real content: @everyone View=Deny (or leave off), BB_Access View=Allow, Unverified View=Deny.
# - Users verify via **bot DM** (Allow DMs from server members). Optional manual #verify-yourself is up to you.
# - Prefer invites that do NOT auto-grant managed access roles; the bot strips them on join and assigns after verify.
# - Bot role must be ABOVE BB_Access / BB-Access in Role list and have Manage Roles or strips fail silently.
# ============================================================

# -----------------------------
# Environment variables required
# -----------------------------
# DISCORD_TOKEN=...
# GUILD_ID=123456789012345678
# Either:
#   DATABASE_URL=postgresql://...
# Or (Supabase split vars):
#   SUPABASE_DB_HOST=db.xxx.supabase.co
#   SUPABASE_DB_PASSWORD=...
# Optional: SUPABASE_DB_PORT=5432 SUPABASE_DB_USER=postgres SUPABASE_DB_NAME=postgres SUPABASE_DB_SSLMODE=require
#
# UNVERIFIED_ROLE_NAME=Unverified
# Optional: legacy Discord role name to remove if present (bot does not assign "Verified" anymore; use DB status)
# VERIFIED_ROLE_NAME=Verified
# ADMIN_ROLE_NAME=Admin
# VERIFICATION_TIMEOUT_HOURS=24
# AUDIT_ON_STARTUP=true
# When true, full compliance audit on boot (all members). Use !audit_bluebird for a scoped sweep.
# Managed access: MANAGED_ACCESS_ROLE_NAMES (whitelist) + optional PROJECT_ROLE_ALIASES; per-user tokens in allocations.projects.
# Verification-exempt staff roles: VERIFICATION_EXEMPT_ROLE_NAMES in this file.
# VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED — unused while in-channel verify stubs are disabled (DM-only flow).
#
# Optional:
# LOG_LEVEL=INFO
# STATUS_CHANNEL_NAME=bot-status
# VERIFY_YOURSELF_TRIGGER_LOG=verify_yourself_triggers.log — JSONL per invite delivered (dm or channel_fallback; empty/false/off to disable)
# VERIFICATION_DM_RETRY_COOLDOWN_MINUTES=20 — min minutes between on_ready DM retries when verification_invite_dm_ok is false


# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("discord-verification-bot")

UTC = timezone.utc

# Discord channel name where the Verify panel lives (must match server; not configurable via env).
VERIFY_CHANNEL_NAME = "verify-yourself"

# JSONL: one line per verification DM sent (env VERIFY_YOURSELF_TRIGGER_LOG — name kept for compatibility).
_vs_trigger_log_path_resolved: Optional[str] = None
_vs_trigger_log_lock = threading.Lock()


def _verification_notice_log_path() -> Optional[str]:
    """Path for JSONL verification-notice log, or None if disabled."""
    global _vs_trigger_log_path_resolved
    if _vs_trigger_log_path_resolved is not None:
        return _vs_trigger_log_path_resolved or None
    raw = os.getenv("VERIFY_YOURSELF_TRIGGER_LOG", "verify_yourself_triggers.log").strip()
    if not raw or raw.lower() in ("none", "false", "0", "off"):
        _vs_trigger_log_path_resolved = ""
        return None
    _vs_trigger_log_path_resolved = raw
    return raw


def log_verification_notice_sent(
    member: discord.Member,
    *,
    notice_trigger: str,
    delivery: str,
    fallback_channel: Optional[str] = None,
) -> None:
    """Append one JSON line when a verification invite is delivered (DM or public channel fallback)."""
    path = _verification_notice_log_path()
    if not path:
        return
    gn = getattr(member, "global_name", None)
    rec: Dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "delivery": delivery,
        "guild_id": str(member.guild.id),
        "guild_name": member.guild.name,
        "user_id": str(member.id),
        "username": member.name,
        "global_name": gn if gn else None,
        "display_name": member.display_name,
        "display": str(member),
        "notice_trigger": notice_trigger,
    }
    if fallback_channel:
        rec["fallback_channel"] = fallback_channel
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    try:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        with _vs_trigger_log_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError as exc:
        logger.warning("verification notice log write failed (%s): %s", path, exc)

# User-facing copy: what they must supply to pass verification / keep access.
VERIFY_REQUIREMENTS_SHORT = (
    "**You must provide:** your **Deccan-associated email address** exactly as on your **active** allocation "
    "(not revoked or banned)."
)

# Optional in-server panel text (in-channel panel auto-post is disabled; verification invites are DM-only).
VERIFY_PANEL_BODY = (
    "**Verification required** to use access channels.\n\n"
    "**What you need to provide:**\n"
    "• **Deccan-associated mail address** — must match **`allocations.email`** on your row\n"
    "• The allocation must be **active** and allowed to verify (not revoked or banned)\n\n"
    "Click **Verify now** below and enter your Deccan-associated email."
)

# DM copy: user taps Verify now here and submits email in the modal (same flow as in-server button).
VERIFY_DM_BODY = (
    "**Verification required** for server channel access.\n\n"
    + VERIFY_REQUIREMENTS_SHORT
    + "\n\nTap **Verify now** below and enter your **email** in the form (must match **`allocations.email`**)."
)

# =============================================================================
# Allocations + managed roles (how it works)
# -----------------------------------------------------------------------------
# Primary operator flow (minimal row: email + projects only — DB defaults active=true, status=ACTIVE):
#   • INSERT row into allocations (email, projects)
#   • User joins → bot strips managed access roles and gates (e.g. Unverified), **DM** with Verify now
#   • User taps Verify now (DM or !helpme) → enters the same email
#   • Bot matches typed email to allocations.email (normalized) → assigns roles from allocations.projects
#
# 1) Table `allocations` (Postgres): one row per person, keyed by `email`. Used to decide **who may verify**
#    (`active`, `status`) and **which** managed roles they get via the **`projects`** text column
#    (comma / semicolon / slash / pipe separated tokens).
#
# 2) **`MANAGED_ACCESS_ROLE_NAMES`** is the whitelist: only those Discord role names may be assigned or held as
#    managed access. Tokens in `projects` must resolve to one of those names (exact match, or via **PROJECT_ROLE_ALIASES**).
#
# 3) On successful verification, the bot confirms the allocation row, then syncs Discord to the **projects** tokens
#    (and **removes** any other managed roles). Same stripping on revoke, gate, failed verify, and audit.
#
# 4) Resync (verified users): if the live allocation row is still verifiable, re-applies **`projects`** roles.
#    If the row is missing or not verifiable, uses the `assigned_roles` JSON snapshot on `discord_user_verification`.
#
# 5) `!audit_bluebird` runs the scoped compliance pass on every member who currently has at least one managed role.
# =============================================================================

# Exact Discord role names the bot is allowed to assign from `allocations.projects` (whitelist). Unlisted roles are
# never assigned; any managed role not allowed for that user is removed on sync.
# Case-sensitive — must match Server Settings → Roles.
MANAGED_ACCESS_ROLE_NAMES: Tuple[str, ...] = (
    "maitrix-QC-coders",
    "maitrix-coders",
    "maitrix-non-coders",
    "maitrix-non_coders-QC",
    "AE_Access",
    "BB_Access",
)
# Optional: map short tokens stored in `allocations.projects` to exact names in MANAGED_ACCESS_ROLE_NAMES.
# Example: {"BB": "BB_Access"}. Keys and values are case-sensitive.
PROJECT_ROLE_ALIASES: Dict[str, str] = {}

# Staff / ops roles: no verification flow; marked exempt in DB; not gated or stripped by compliance.
# Case-sensitive — must match Server Settings → Roles exactly.
VERIFICATION_EXEMPT_ROLE_NAMES: Tuple[str, ...] = (
    "Admin",
    "Support",
    "AE-Manager",
    "BB-Manager",
    "MAITRIX-moderator",
)


# ============================================================
# Config
# ============================================================
@dataclass
class Settings:
    discord_token: str
    guild_id: int
    database_url: str
    unverified_role_name: str = "Unverified"
    verified_role_name: str = "Verified"
    admin_role_name: str = "Admin"
    verification_timeout_hours: int = 24
    audit_on_startup: bool = True
    status_channel_name: Optional[str] = None
    managed_access_role_names: set[str] = field(default_factory=set)
    verification_exempt_role_names: set[str] = field(default_factory=set)
    restrict_verify_channel_to_unverified: bool = True
    verification_dm_retry_cooldown_minutes: int = 20


def resolve_database_url() -> str:
    """Prefer DATABASE_URL; otherwise build from SUPABASE_DB_* (common on Render/Supabase)."""
    direct = os.getenv("DATABASE_URL", "").strip()
    if direct:
        return direct

    host = os.getenv("SUPABASE_DB_HOST", "").strip()
    if not host:
        return ""

    port = os.getenv("SUPABASE_DB_PORT", "5432").strip() or "5432"
    user = os.getenv("SUPABASE_DB_USER", "postgres").strip() or "postgres"
    password = os.getenv("SUPABASE_DB_PASSWORD", "")
    dbname = os.getenv("SUPABASE_DB_NAME", "postgres").strip() or "postgres"
    sslmode = os.getenv("SUPABASE_DB_SSLMODE", "require").strip()

    if not password:
        raise RuntimeError(
            "SUPABASE_DB_PASSWORD is required when using SUPABASE_DB_HOST (or set DATABASE_URL)."
        )

    user_q = quote_plus(user)
    pass_q = quote_plus(password)
    q = f"?sslmode={quote_plus(sslmode)}" if sslmode else ""
    return f"postgresql://{user_q}:{pass_q}@{host}:{port}/{dbname}{q}"


def get_settings() -> Settings:
    missing = []

    def require(name: str) -> str:
        value = os.getenv(name)
        if not value:
            missing.append(name)
            return ""
        return value

    try:
        database_url = resolve_database_url()
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc

    if not database_url:
        missing.append("DATABASE_URL or (SUPABASE_DB_HOST + SUPABASE_DB_PASSWORD)")

    managed = set(MANAGED_ACCESS_ROLE_NAMES)
    if not managed:
        raise RuntimeError(
            "MANAGED_ACCESS_ROLE_NAMES in bot_verifier.py must contain at least one Discord role name."
        )
    for alias_key, alias_val in PROJECT_ROLE_ALIASES.items():
        if alias_val not in managed:
            raise RuntimeError(
                f"PROJECT_ROLE_ALIASES[{alias_key!r}] -> {alias_val!r} must be an entry in MANAGED_ACCESS_ROLE_NAMES."
            )

    settings = Settings(
        discord_token=require("DISCORD_TOKEN"),
        guild_id=int(require("GUILD_ID") or 0),
        database_url=database_url if database_url else "",
        unverified_role_name=os.getenv("UNVERIFIED_ROLE_NAME", "Unverified"),
        verified_role_name=os.getenv("VERIFIED_ROLE_NAME", "Verified"),
        admin_role_name=os.getenv("ADMIN_ROLE_NAME", "Admin"),
        verification_timeout_hours=int(os.getenv("VERIFICATION_TIMEOUT_HOURS", "24")),
        audit_on_startup=os.getenv("AUDIT_ON_STARTUP", "true").lower() == "true",
        status_channel_name=os.getenv("STATUS_CHANNEL_NAME"),
        managed_access_role_names=managed,
        verification_exempt_role_names=set(VERIFICATION_EXEMPT_ROLE_NAMES),
        restrict_verify_channel_to_unverified=os.getenv(
            "VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED", "true"
        ).lower()
        in ("1", "true", "yes"),
        verification_dm_retry_cooldown_minutes=max(
            1, int(os.getenv("VERIFICATION_DM_RETRY_COOLDOWN_MINUTES", "20"))
        ),
    )

    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return settings


SETTINGS = get_settings()

PORT = int(os.getenv("PORT", "8080"))
ADMIN_PANEL_CHANNEL_NAME = os.getenv("ADMIN_PANEL_CHANNEL_NAME", "admin-management")
SUPPORT_ROLE_NAME = os.getenv("SUPPORT_ROLE_NAME", "Support")

# One reconnect/retry sweep at a time (on_ready may fire multiple times).
_verification_invite_retry_lock: Optional[asyncio.Lock] = None


def _verification_invite_retry_lock_get() -> asyncio.Lock:
    global _verification_invite_retry_lock
    if _verification_invite_retry_lock is None:
        _verification_invite_retry_lock = asyncio.Lock()
    return _verification_invite_retry_lock


def norm_str(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value).strip().lower())


def allocation_row_is_active(row: Dict[str, Any]) -> bool:
    v = row.get("active", True)
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"true", "1", "yes", "y"}


def allocation_status_allows_verify(row: Dict[str, Any]) -> bool:
    """ACTIVE or unset; REVOKE / BAN block verification (set by !kick / !ban)."""
    st = row.get("status")
    if st is None or st == "":
        return True
    u = str(st).strip().upper()
    if u in ("REVOKE", "BAN"):
        return False
    return True


def allocation_row_can_verify(row: Dict[str, Any]) -> bool:
    if not allocation_row_is_active(row):
        return False
    return allocation_status_allows_verify(row)


_PROJECT_SEP_RE = re.compile(r"[,;/|]+")

# Detected at DB connect time; None until connect() runs.
_PROJECTS_COL_IS_ARRAY: Optional[bool] = None


def _projects_to_db(tokens: List[str]) -> Any:
    """Return the correct value to pass to asyncpg for allocations.projects.

    asyncpg maps Python list → PostgreSQL TEXT[]; TEXT columns want a plain string.
    Detected once at startup from information_schema.
    """
    if _PROJECTS_COL_IS_ARRAY:
        return tokens
    return ",".join(tokens)


def split_projects_str(projects: Any) -> List[str]:
    """Split `allocations.projects` into role tokens.

    - **TEXT** column: split on comma, semicolon, slash, or pipe; trim; drop empties.
    - **PostgreSQL ARRAY** (e.g. ``text[]``): asyncpg returns a Python ``list`` — one token per element (no ``str(list)``).
    """
    if projects is None:
        return []
    if isinstance(projects, (list, tuple)):
        out: List[str] = []
        for p in projects:
            if p is None:
                continue
            t = str(p).strip()
            if t:
                out.append(t)
        return out
    s = str(projects).strip()
    if not s:
        return []
    return [p.strip() for p in _PROJECT_SEP_RE.split(s) if p.strip()]


def get_managed_role_tokens_for_verified_allocation(row: Dict[str, Any]) -> List[str]:
    """
    If the allocation row allows verification, return role tokens from `allocations.projects` (deduped, order kept).
    Each token must resolve via PROJECT_ROLE_ALIASES or exact name to MANAGED_ACCESS_ROLE_NAMES to be assigned.
    """
    if not allocation_row_can_verify(row):
        return []
    return list(dict.fromkeys(split_projects_str(row.get("projects"))))


# ============================================================
# Database layer
# ============================================================
class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        # statement_cache_size=0: required for Supabase pooler / PgBouncer (transaction mode breaks prepared stmts)
        self.pool = await asyncpg.create_pool(
            self.dsn, min_size=1, max_size=5, statement_cache_size=0
        )
        await self.init_schema()
        await self._detect_projects_col_type()
        logger.info("Connected to database")

    async def _detect_projects_col_type(self) -> None:
        """Detect whether allocations.projects is TEXT or TEXT[] and cache the result."""
        global _PROJECTS_COL_IS_ARRAY
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name   = 'allocations'
                  AND column_name  = 'projects'
                """
            )
        if row:
            _PROJECTS_COL_IS_ARRAY = row["data_type"].upper() in ("ARRAY",)
        else:
            _PROJECTS_COL_IS_ARRAY = False
        logger.info(
            "allocations.projects column type: %s (is_array=%s)",
            row["data_type"] if row else "unknown",
            _PROJECTS_COL_IS_ARRAY,
        )

    async def init_schema(self) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS discord_user_verification (
                    discord_user_id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL,
                    discord_username TEXT,
                    email TEXT,
                    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                    verification_status TEXT NOT NULL DEFAULT 'pending',
                    verified_at TIMESTAMPTZ,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    verification_attempts INT NOT NULL DEFAULT 0,
                    last_error TEXT,
                    assigned_projects JSONB NOT NULL DEFAULT '[]'::jsonb,
                    assigned_roles JSONB NOT NULL DEFAULT '[]'::jsonb,
                    source_row JSONB,
                    verification_locked BOOLEAN NOT NULL DEFAULT FALSE,
                    removed_for_timeout BOOLEAN NOT NULL DEFAULT FALSE,
                    access_revoked BOOLEAN NOT NULL DEFAULT FALSE
                );

                CREATE INDEX IF NOT EXISTS idx_duv_guild_status
                ON discord_user_verification (guild_id, verification_status);

                CREATE INDEX IF NOT EXISTS idx_duv_email
                ON discord_user_verification (email);

                ALTER TABLE discord_user_verification
                ADD COLUMN IF NOT EXISTS access_revoked BOOLEAN NOT NULL DEFAULT FALSE;

                CREATE INDEX IF NOT EXISTS idx_duv_access_revoked
                ON discord_user_verification (guild_id, access_revoked)
                WHERE access_revoked = TRUE;

                ALTER TABLE discord_user_verification ADD COLUMN IF NOT EXISTS status TEXT;
                UPDATE discord_user_verification
                SET status = 'VERIFIED'
                WHERE is_verified IS TRUE AND verification_locked IS TRUE
                  AND (status IS NULL OR status = '');
                UPDATE discord_user_verification
                SET status = 'NOT_VERIFIED'
                WHERE status IS NULL OR status = '';
                ALTER TABLE discord_user_verification ALTER COLUMN status SET DEFAULT 'NOT_VERIFIED';
                ALTER TABLE discord_user_verification ALTER COLUMN status SET NOT NULL;

                ALTER TABLE discord_user_verification
                ADD COLUMN IF NOT EXISTS verification_invite_dm_ok BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE discord_user_verification
                ADD COLUMN IF NOT EXISTS verification_invite_last_attempt_at TIMESTAMPTZ;

                CREATE TABLE IF NOT EXISTS allocations (
                    email TEXT PRIMARY KEY,
                    full_name TEXT,
                    projects TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                ALTER TABLE allocations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';
                UPDATE allocations SET status = 'ACTIVE' WHERE status IS NULL OR status = '';
                """
            )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                DROP INDEX IF EXISTS idx_duv_soul_id;
                DROP INDEX IF EXISTS idx_allocations_email;
                ALTER TABLE discord_user_verification DROP COLUMN IF EXISTS soul_id;

                DO $migrate_allocations$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = 'allocations'
                          AND column_name = 'soul_id'
                    ) THEN
                        ALTER TABLE allocations DROP CONSTRAINT IF EXISTS allocations_pkey;
                        ALTER TABLE allocations DROP COLUMN soul_id;
                        ALTER TABLE allocations ADD PRIMARY KEY (email);
                    END IF;
                END
                $migrate_allocations$;

                DROP INDEX IF EXISTS idx_allocations_discord_email;
                ALTER TABLE allocations DROP COLUMN IF EXISTS discord_email;
                """
            )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bot_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    id               BIGSERIAL PRIMARY KEY,
                    actor_discord_id TEXT NOT NULL,
                    actor_username   TEXT NOT NULL,
                    action           TEXT NOT NULL,
                    target_email     TEXT,
                    target_discord_id TEXT,
                    details          JSONB,
                    performed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_aal_performed_at
                    ON admin_audit_log (performed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_aal_actor
                    ON admin_audit_log (actor_discord_id);
                """
            )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_removal (
                    id               BIGSERIAL PRIMARY KEY,
                    discord_user_id  TEXT,
                    email            TEXT,
                    discord_username TEXT,
                    reason           TEXT,
                    removed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    removed_by       TEXT NOT NULL DEFAULT 'system'
                );
                CREATE INDEX IF NOT EXISTS idx_user_removal_discord_user_id
                    ON user_removal (discord_user_id);
                CREATE INDEX IF NOT EXISTS idx_user_removal_email
                    ON user_removal (email);
                """
            )

    async def touch_user(self, guild_id: int, member: discord.Member) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id, discord_username, last_seen_at
                ) VALUES ($1, $2, $3, NOW())
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    guild_id = EXCLUDED.guild_id,
                    discord_username = EXCLUDED.discord_username,
                    last_seen_at = NOW();
                """,
                str(member.id),
                str(guild_id),
                str(member),
            )

    async def get_user(self, discord_user_id: int) -> Optional[asyncpg.Record]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM discord_user_verification WHERE discord_user_id = $1",
                str(discord_user_id),
            )

    async def record_verification_invite_outcome(
        self, discord_user_id: int, *, dm_ok: bool, guild_id: int
    ) -> None:
        """Track whether the last invite was delivered by DM; always bumps last_attempt_at for retry cooldown."""
        assert self.pool is not None
        uid = str(discord_user_id)
        gid = str(guild_id)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id,
                    verification_invite_dm_ok, verification_invite_last_attempt_at, last_seen_at
                ) VALUES ($1, $2, $3, NOW(), NOW())
                ON CONFLICT (discord_user_id) DO UPDATE SET
                    verification_invite_dm_ok = EXCLUDED.verification_invite_dm_ok,
                    verification_invite_last_attempt_at = NOW(),
                    last_seen_at = NOW();
                """,
                uid,
                gid,
                dm_ok,
            )

    async def list_discord_user_ids_pending_invite_dm_retry(
        self, guild_id: str, min_minutes_since_attempt: int
    ) -> List[asyncpg.Record]:
        """
        Users who still need verification, never got a successful DM invite (dm_ok=false), and are past cooldown
        since last attempt — used to re-try DM after bot restart / reconnect (transient failures).
        """
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT discord_user_id
                FROM discord_user_verification
                WHERE guild_id = $1
                  AND status = 'NOT_VERIFIED'
                  AND COALESCE(access_revoked, FALSE) = FALSE
                  AND verification_invite_dm_ok = FALSE
                  AND COALESCE(verification_status, '') <> 'exempt'
                  AND (
                    verification_invite_last_attempt_at IS NULL
                    OR verification_invite_last_attempt_at < NOW() - ($2::int * INTERVAL '1 minute')
                  )
                """,
                guild_id,
                min_minutes_since_attempt,
            )

    async def mark_failed_attempt(self, discord_user_id: int, error: str) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (discord_user_id, guild_id, last_error, verification_attempts)
                VALUES ($1, $2, $3, 1)
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    verification_status = 'failed',
                    last_error = EXCLUDED.last_error,
                    verification_attempts = discord_user_verification.verification_attempts + 1,
                    status = 'NOT_VERIFIED',
                    last_seen_at = NOW();
                """,
                str(discord_user_id),
                str(SETTINGS.guild_id),
                error,
            )

    async def mark_verified(
        self,
        discord_user_id: int,
        guild_id: int,
        member_name: str,
        email: str,
        assigned_projects: List[str],
        assigned_roles: List[str],
        source_row: Dict[str, Any],
    ) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id,
                    guild_id,
                    discord_username,
                    email,
                    is_verified,
                    verification_status,
                    verified_at,
                    last_seen_at,
                    assigned_projects,
                    assigned_roles,
                    source_row,
                    verification_locked,
                    removed_for_timeout,
                    access_revoked,
                    status
                ) VALUES (
                    $1, $2, $3, $4, TRUE, 'verified', NOW(), NOW(), $5::jsonb, $6::jsonb, $7::jsonb, TRUE, FALSE, FALSE, 'VERIFIED'
                )
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    guild_id = EXCLUDED.guild_id,
                    discord_username = EXCLUDED.discord_username,
                    email = EXCLUDED.email,
                    is_verified = TRUE,
                    verification_status = 'verified',
                    verified_at = NOW(),
                    last_seen_at = NOW(),
                    assigned_projects = EXCLUDED.assigned_projects,
                    assigned_roles = EXCLUDED.assigned_roles,
                    source_row = EXCLUDED.source_row,
                    verification_locked = TRUE,
                    removed_for_timeout = FALSE,
                    access_revoked = FALSE,
                    status = 'VERIFIED',
                    last_error = NULL,
                    verification_invite_dm_ok = TRUE;
                """,
                str(discord_user_id),
                str(guild_id),
                member_name,
                email,
                json.dumps(assigned_projects),
                json.dumps(assigned_roles),
                json.dumps(source_row, default=str),
            )

    async def mark_verification_exempt(self, guild_id: int, member: discord.Member) -> None:
        """Staff/ops: no allocation; DB marked VERIFIED with verification_status=exempt (compliance skips stripping)."""
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id, discord_username, last_seen_at,
                    is_verified, verification_status, verified_at, verification_locked,
                    status, access_revoked, removed_for_timeout,
                    assigned_projects, assigned_roles, last_error
                ) VALUES (
                    $1, $2, $3, NOW(),
                    TRUE, 'exempt', NOW(), TRUE,
                    'VERIFIED', FALSE, FALSE,
                    '[]'::jsonb, '[]'::jsonb, NULL
                )
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    guild_id = EXCLUDED.guild_id,
                    discord_username = EXCLUDED.discord_username,
                    last_seen_at = NOW(),
                    is_verified = TRUE,
                    verification_status = 'exempt',
                    verified_at = COALESCE(discord_user_verification.verified_at, NOW()),
                    verification_locked = TRUE,
                    status = 'VERIFIED',
                    access_revoked = FALSE,
                    removed_for_timeout = FALSE,
                    assigned_projects = '[]'::jsonb,
                    assigned_roles = '[]'::jsonb,
                    source_row = NULL,
                    email = NULL,
                    last_error = NULL;
                """,
                str(member.id),
                str(guild_id),
                str(member),
            )

    async def clear_verification_exempt_record_state(self, discord_user_id: int) -> None:
        """If DB says exempt but member no longer has exempt role, reset to pending / NOT_VERIFIED."""
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE discord_user_verification SET
                    verification_status = 'pending',
                    status = 'NOT_VERIFIED',
                    is_verified = FALSE,
                    verification_locked = FALSE,
                    verified_at = NULL,
                    verification_invite_dm_ok = FALSE,
                    verification_invite_last_attempt_at = NULL,
                    last_seen_at = NOW()
                WHERE discord_user_id = $1 AND verification_status = 'exempt';
                """,
                str(discord_user_id),
            )

    async def mark_timeout_removed(self, discord_user_id: int, reason: str) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id, verification_status, removed_for_timeout, last_error, status
                ) VALUES ($1, $2, 'timed_out', TRUE, $3, 'NOT_VERIFIED')
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    verification_status = 'timed_out',
                    removed_for_timeout = TRUE,
                    last_error = EXCLUDED.last_error,
                    status = 'NOT_VERIFIED',
                    verification_invite_dm_ok = FALSE,
                    verification_invite_last_attempt_at = NULL,
                    last_seen_at = NOW();
                """,
                str(discord_user_id),
                str(SETTINGS.guild_id),
                reason,
            )

    async def reset_user(self, discord_user_id: int) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE discord_user_verification
                SET is_verified = FALSE,
                    verification_status = 'pending',
                    verification_locked = FALSE,
                    verified_at = NULL,
                    assigned_projects = '[]'::jsonb,
                    assigned_roles = '[]'::jsonb,
                    last_error = NULL,
                    removed_for_timeout = FALSE,
                    access_revoked = FALSE,
                    status = 'NOT_VERIFIED',
                    verification_invite_dm_ok = FALSE,
                    verification_invite_last_attempt_at = NULL,
                    last_seen_at = NOW()
                WHERE discord_user_id = $1;
                """,
                str(discord_user_id),
            )

    async def get_stale_unverified_users(self, timeout_hours: int) -> List[asyncpg.Record]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT *
                FROM discord_user_verification
                WHERE guild_id = $1
                  AND status = 'NOT_VERIFIED'
                  AND verification_status IN ('pending', 'failed')
                  AND first_seen_at <= NOW() - ($2 || ' hours')::interval
                """,
                str(SETTINGS.guild_id),
                str(timeout_hours),
            )

    async def get_pending_revoke_users(self) -> List[asyncpg.Record]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT *
                FROM discord_user_verification
                WHERE guild_id = $1
                  AND access_revoked = TRUE
                """,
                str(SETTINGS.guild_id),
            )

    async def set_access_revoked_pending(self, discord_user_id: int) -> None:
        """Flag user for revoke; poll or !revoke_access will apply Discord + DB."""
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id, access_revoked, last_seen_at
                ) VALUES ($1, $2, TRUE, NOW())
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    access_revoked = TRUE,
                    last_seen_at = NOW();
                """,
                str(discord_user_id),
                str(SETTINGS.guild_id),
            )

    async def apply_revoke_completed(self, discord_user_id: int) -> None:
        """Clear revoke flag and verification after access has been removed in Discord."""
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE discord_user_verification
                SET access_revoked = FALSE,
                    is_verified = FALSE,
                    verification_locked = FALSE,
                    verification_status = 'revoked',
                    verified_at = NULL,
                    assigned_projects = '[]'::jsonb,
                    assigned_roles = '[]'::jsonb,
                    source_row = NULL,
                    last_error = NULL,
                    removed_for_timeout = FALSE,
                    status = 'NOT_VERIFIED',
                    verification_invite_dm_ok = FALSE,
                    verification_invite_last_attempt_at = NULL,
                    last_seen_at = NOW()
                WHERE discord_user_id = $1;
                """,
                str(discord_user_id),
            )

    async def set_allocation_status_by_email(self, allocation_email: str, status: str) -> bool:
        """Set allocations.status (e.g. REVOKE, BAN) by primary key `email`. Returns True if a row was updated."""
        assert self.pool is not None
        em = allocation_email.strip()
        if not em:
            return False
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE allocations
                SET status = $2, updated_at = NOW()
                WHERE email = $1
                RETURNING email
                """,
                em,
                status,
            )
        return row is not None

    async def fetch_allocations(self) -> List[Dict[str, Any]]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT email, full_name, projects, active, status
                FROM allocations
                """
            )
        return [dict(r) for r in rows]

    async def fetch_allocation_by_email(self, allocation_email: str) -> Optional[Dict[str, Any]]:
        """Single allocation row by primary key `email` (for resyncing verified users)."""
        em = (allocation_email or "").strip()
        if not em:
            return None
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT email, full_name, projects, active, status
                FROM allocations
                WHERE email = $1
                """,
                em,
            )
        return dict(row) if row else None

    async def find_allocation_match(self, email: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Match Verify-modal input to **allocations.email** (normalized: lowercase, whitespace removed)."""
        rows = await self.fetch_allocations()
        email_n = norm_str(email)
        matches: List[Dict[str, Any]] = []
        for row in rows:
            row_email = norm_str(row.get("email"))
            if row_email == email_n:
                matches.append(row)

        if not matches:
            return False, None, "No matching user found in allocations for that email."
        if len(matches) > 1:
            return (
                False,
                None,
                "Multiple allocations share this email — contact an admin.",
            )

        row = matches[0]
        if not allocation_row_can_verify(row):
            if not allocation_row_is_active(row):
                return False, row, "Allocation is inactive (active=false)."
            return False, row, "This allocation is revoked or banned."
        return True, row, "matched"

    async def get_setting(self, key: str) -> Optional[str]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM bot_settings WHERE key = $1", key
            )
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO bot_settings (key, value, updated_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                """,
                key,
                value,
            )

    async def log_admin_action(
        self,
        actor: discord.Member,
        action: str,
        *,
        target_email: Optional[str] = None,
        target_discord_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO admin_audit_log
                    (actor_discord_id, actor_username, action,
                     target_email, target_discord_id, details)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                """,
                str(actor.id),
                str(actor),
                action,
                target_email,
                str(target_discord_id) if target_discord_id is not None else None,
                json.dumps(details) if details is not None else None,
            )

    async def insert_user_removal(
        self,
        discord_user_id: Optional[int],
        email: Optional[str],
        discord_username: Optional[str],
        reason: str,
        removed_by: str = "system",
    ) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO user_removal
                    (discord_user_id, email, discord_username, reason, removed_by)
                VALUES ($1, $2, $3, $4, $5)
                """,
                str(discord_user_id) if discord_user_id is not None else None,
                email,
                discord_username,
                reason,
                removed_by,
            )

    async def load_role_config(self) -> None:
        """Load managed/exempt role lists from bot_settings; mutates SETTINGS in place. Falls back to hardcoded defaults."""
        for key, target_set, default_tuple in [
            ("managed_access_roles", SETTINGS.managed_access_role_names, MANAGED_ACCESS_ROLE_NAMES),
            ("verification_exempt_roles", SETTINGS.verification_exempt_role_names, VERIFICATION_EXEMPT_ROLE_NAMES),
        ]:
            val = await self.get_setting(key)
            if val:
                try:
                    loaded = json.loads(val)
                    if isinstance(loaded, list) and all(isinstance(x, str) for x in loaded):
                        target_set.clear()
                        target_set.update(loaded)
                        logger.info("Role config: loaded '%s' from DB: %s", key, loaded)
                        continue
                except json.JSONDecodeError:
                    logger.warning("bot_settings key '%s' has invalid JSON — using hardcoded default", key)
            target_set.clear()
            target_set.update(default_tuple)

        aliases_val = await self.get_setting("project_role_aliases")
        if aliases_val:
            try:
                loaded_aliases = json.loads(aliases_val)
                if isinstance(loaded_aliases, dict):
                    PROJECT_ROLE_ALIASES.clear()
                    PROJECT_ROLE_ALIASES.update(loaded_aliases)
                    logger.info("Role config: loaded project_role_aliases from DB")
            except json.JSONDecodeError:
                logger.warning("bot_settings key 'project_role_aliases' has invalid JSON — using hardcoded default")

    async def save_role_config(
        self,
        managed: Optional[List[str]] = None,
        exempt: Optional[List[str]] = None,
        aliases: Optional[Dict[str, str]] = None,
    ) -> None:
        if managed is not None:
            await self.set_setting("managed_access_roles", json.dumps(sorted(managed)))
        if exempt is not None:
            await self.set_setting("verification_exempt_roles", json.dumps(sorted(exempt)))
        if aliases is not None:
            await self.set_setting("project_role_aliases", json.dumps(aliases))


# ============================================================
# Discord bot
# ============================================================
intents = discord.Intents.default()
intents.guilds = True
intents.members = True  # Enable "Server Members Intent" in the Developer Portal.
intents.message_content = True  # Enable "Message Content Intent" for !commands (Portal).

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
db = Database(SETTINGS.database_url)

# Only one full guild compliance audit at a time (startup + 30m loop + manual must not overlap).
_compliance_audit_lock = asyncio.Lock()


# ============================================================
# Helpers
# ============================================================
def member_db_verified(record: Optional[Any]) -> bool:
    """True if the user is verified per DB `status` (or legacy is_verified + verification_locked)."""
    if not record:
        return False
    if str(record.get("verification_status") or "").strip().lower() == "exempt":
        return True
    st = record.get("status")
    if isinstance(st, str):
        st = st.strip().upper()
    if st == "VERIFIED":
        return True
    if st == "NOT_VERIFIED":
        return False
    return bool(record.get("is_verified") and record.get("verification_locked"))


def verification_source_row_dict(record: Any) -> Optional[Dict[str, Any]]:
    """Parse `source_row` JSONB from a verification record into a dict."""
    if not record:
        return None
    sr = record.get("source_row")
    if sr is None:
        return None
    if isinstance(sr, dict):
        return sr
    if isinstance(sr, str):
        try:
            return json.loads(sr)
        except json.JSONDecodeError:
            return None
    return None


def get_role(guild: discord.Guild, role_name: str) -> Optional[discord.Role]:
    return discord.utils.get(guild.roles, name=role_name)


def get_channel_by_name(guild: discord.Guild, channel_name: str) -> Optional[discord.abc.GuildChannel]:
    return discord.utils.get(guild.channels, name=channel_name)


def member_is_verification_exempt(member: discord.Member) -> bool:
    """True if the member has any role listed in VERIFICATION_EXEMPT_ROLE_NAMES / settings."""
    if member.bot:
        return False
    for role in member.roles:
        if role.name in SETTINGS.verification_exempt_role_names:
            return True
    return False


def is_access_role_name(name: str) -> bool:
    """True if this Discord role name is in MANAGED_ACCESS_ROLE_NAMES (exact match)."""
    n = (name or "").strip()
    if not n:
        return False
    return n in SETTINGS.managed_access_role_names


def resolve_project_role(guild: discord.Guild, project_token: str) -> Optional[discord.Role]:
    """
    Resolve a token from `allocations.projects` to a guild role: optional PROJECT_ROLE_ALIASES, then whitelist check.
    """
    t = project_token.strip()
    if not t:
        return None
    name = PROJECT_ROLE_ALIASES.get(t, t)
    if name not in SETTINGS.managed_access_role_names:
        return None
    return get_role(guild, name)


def members_with_any_managed_access_role(guild: discord.Guild) -> List[discord.Member]:
    """Members (non-bot) who hold at least one role in MANAGED_ACCESS_ROLE_NAMES."""
    out: List[discord.Member] = []
    seen: set[int] = set()
    for m in guild.members:
        if m.bot or m.id in seen:
            continue
        for r in m.roles:
            if r.name in SETTINGS.managed_access_role_names:
                out.append(m)
                seen.add(m.id)
                break
    return out


async def ensure_roles_exist(guild: discord.Guild) -> None:
    """Ensure the gate role (Unverified) exists; we do not create a Discord Verified role."""
    if not get_role(guild, SETTINGS.unverified_role_name):
        await guild.create_role(name=SETTINGS.unverified_role_name, reason="Required verification gate role")
        logger.info("Created missing role: %s", SETTINGS.unverified_role_name)


async def assign_role_if_missing(member: discord.Member, role_name: str, reason: str) -> bool:
    role = get_role(member.guild, role_name)
    if not role:
        logger.warning("Role not found: %s", role_name)
        return False
    if role in member.roles:
        return False
    await member.add_roles(role, reason=reason)
    return True


async def remove_role_if_present(member: discord.Member, role_name: str, reason: str) -> bool:
    role = get_role(member.guild, role_name)
    if not role:
        return False
    if role not in member.roles:
        return False
    await member.remove_roles(role, reason=reason)
    return True


async def remove_all_access_roles(member: discord.Member) -> List[str]:
    removed = []
    for role in list(member.roles):
        if is_access_role_name(role.name):
            await member.remove_roles(role, reason="Removing project access roles")
            removed.append(role.name)
    return removed


def allowed_managed_access_names_from_tokens(
    guild: discord.Guild, role_tokens: List[str]
) -> frozenset[str]:
    """Resolve `allocations.projects` tokens (after aliases) to Discord roles present on this guild."""
    names: set[str] = set()
    for token in role_tokens:
        role = resolve_project_role(guild, token)
        if role:
            names.add(role.name)
        else:
            logger.warning(
                "projects token '%s' did not resolve (not in MANAGED_ACCESS_ROLE_NAMES / PROJECT_ROLE_ALIASES, or no matching role on server)",
                token,
            )
    return frozenset(names)


async def sync_managed_access_roles(
    member: discord.Member, allowed_names: frozenset[str], reason: str
) -> List[str]:
    """
    Remove managed access roles not in allowed_names; add allowed roles that are missing.
    Returns sorted role names that are both allowed and present on the member after sync (for DB assigned_roles).
    """
    to_remove = [
        r
        for r in member.roles
        if is_access_role_name(r.name) and r.name not in allowed_names
    ]
    if to_remove:
        try:
            await member.remove_roles(*to_remove, reason=reason)
        except discord.HTTPException as exc:
            logger.warning(
                "sync_managed_access_roles: could not remove extra roles %s: %s",
                [r.name for r in to_remove],
                exc,
            )

    to_add: List[discord.Role] = []
    for name in allowed_names:
        role = get_role(member.guild, name)
        if not role:
            logger.warning(
                "sync_managed_access_roles: allowed role '%s' not defined on server",
                name,
            )
            continue
        if role not in member.roles:
            to_add.append(role)
    if to_add:
        try:
            await member.add_roles(*to_add, reason=reason)
        except discord.HTTPException as exc:
            logger.warning(
                "sync_managed_access_roles: could not add roles %s: %s",
                [r.name for r in to_add],
                exc,
            )

    out: List[str] = []
    for name in sorted(allowed_names):
        role = get_role(member.guild, name)
        if role and role in member.roles:
            out.append(name)
    return out


async def resync_verified_member_roles(member: discord.Member, record: Any, reason: str) -> None:
    """
    Clear verification gate roles, then restore managed access roles from current `allocations` row (by stored `email` PK),
    or from `assigned_roles` JSON snapshot if allocation is missing or not verifiable.
    Exempt staff (by role or DB verification_status=exempt) never get allocation-driven role sync — only Unverified cleared.
    """
    if member_is_verification_exempt(member):
        await db.mark_verification_exempt(member.guild.id, member)
        await remove_role_if_present(member, SETTINGS.unverified_role_name, reason)
        await remove_role_if_present(member, SETTINGS.verified_role_name, f"{reason} (legacy Verified role)")
        return
    if record and str(record.get("verification_status") or "").strip().lower() == "exempt":
        if member_is_verification_exempt(member):
            await remove_role_if_present(member, SETTINGS.unverified_role_name, reason)
            await remove_role_if_present(member, SETTINGS.verified_role_name, f"{reason} (legacy Verified role)")
            return
        await db.clear_verification_exempt_record_state(member.id)
        record = await db.get_user(member.id)

    await remove_role_if_present(member, SETTINGS.unverified_role_name, reason)
    await remove_role_if_present(member, SETTINGS.verified_role_name, f"{reason} (legacy Verified role)")

    alloc_email = (record.get("email") or "").strip() if record else ""
    if not alloc_email:
        srd = verification_source_row_dict(record)
        if srd:
            alloc_email = str(srd.get("email") or "").strip()
    alloc: Optional[Dict[str, Any]] = None
    if alloc_email:
        alloc = await db.fetch_allocation_by_email(alloc_email)
    if alloc and allocation_row_can_verify(alloc):
        tokens = get_managed_role_tokens_for_verified_allocation(alloc)
        allowed = allowed_managed_access_names_from_tokens(member.guild, tokens)
        await sync_managed_access_roles(member, allowed, reason)
        return
    assigned_roles = record.get("assigned_roles") or [] if record else []
    if isinstance(assigned_roles, str):
        assigned_roles = json.loads(assigned_roles)
    allowed = frozenset(
        s
        for s in (str(x).strip() for x in assigned_roles)
        if s in SETTINGS.managed_access_role_names
    )
    await sync_managed_access_roles(member, allowed, f"{reason} (DB snapshot)")


def member_access_role_names(member: discord.Member) -> List[str]:
    return [r.name for r in member.roles if is_access_role_name(r.name)]


async def gate_member(member: discord.Member, reason: str) -> None:
    """Add Unverified; remove legacy Verified role. Does not remove managed access roles (use revoke_member_access for verify-first)."""
    await assign_role_if_missing(member, SETTINGS.unverified_role_name, reason)
    await remove_role_if_present(member, SETTINGS.verified_role_name, reason)


async def _resolve_member_by_query(guild: discord.Guild, query: str) -> Optional[discord.Member]:
    """Resolve a username, display name, or numeric ID string to a guild Member."""
    query = query.strip()
    if not query:
        return None
    if query.isdigit():
        member = guild.get_member(int(query))
        if member is None:
            try:
                member = await guild.fetch_member(int(query))
            except discord.NotFound:
                pass
        if member:
            return member
    q = query.lower()
    for m in guild.members:
        if m.bot:
            continue
        if m.name.lower() == q or m.display_name.lower() == q:
            return m
    for m in guild.members:
        if m.bot:
            continue
        if q in m.name.lower() or q in m.display_name.lower():
            return m
    return None


async def _strip_inactive_allocation_member(
    member: discord.Member,
    email: str,
    reason: str,
    removed_by: str = "system",
) -> bool:
    """Strip all managed access roles from a member whose allocation.active=False. Returns True if any roles were removed."""
    removed = await remove_all_access_roles(member)
    if not removed:
        return False
    await db.apply_revoke_completed(member.id)
    await db.insert_user_removal(
        discord_user_id=member.id,
        email=email,
        discord_username=str(member),
        reason=reason,
        removed_by=removed_by,
    )
    logger.info("Stripped inactive-allocation member %s (email=%s)", member.id, email)
    return True


async def revoke_member_access(member: discord.Member, reason: str) -> None:
    """Gate plus remove all managed access roles (hard revocation)."""
    await gate_member(member, reason)
    await remove_all_access_roles(member)


async def finalize_verified_member(
    member: discord.Member, source_row: Dict[str, Any], typed_email: str
) -> Tuple[List[str], List[str]]:
    """
    Identity verified: remove Unverified / legacy Verified; assign managed roles from `allocations.projects`.
    Stores canonical `allocations.email` (PK) on the verification row for resync and kick/ban.
    Returns (role_tokens_logged, assigned_role_names).
    """
    canonical_email = str(source_row.get("email") or "").strip() or typed_email.strip()
    await remove_role_if_present(member, SETTINGS.unverified_role_name, "Verification success")
    await remove_role_if_present(member, SETTINGS.verified_role_name, "Verification success (legacy Verified role)")
    tokens_logged = get_managed_role_tokens_for_verified_allocation(source_row)
    allowed = allowed_managed_access_names_from_tokens(member.guild, tokens_logged)
    assigned_roles = await sync_managed_access_roles(
        member, allowed, "Verification success: allocation projects"
    )
    await db.mark_verified(
        discord_user_id=member.id,
        guild_id=member.guild.id,
        member_name=str(member),
        email=canonical_email,
        assigned_projects=tokens_logged,
        assigned_roles=assigned_roles,
        source_row=source_row,
    )
    return tokens_logged, assigned_roles


async def send_status_message(guild: discord.Guild, content: str) -> None:
    if not SETTINGS.status_channel_name:
        return
    channel = get_channel_by_name(guild, SETTINGS.status_channel_name)
    if channel and isinstance(channel, discord.TextChannel):
        try:
            await channel.send(content)
        except Exception as e:
            logger.warning("Could not send status message: %s", e)


async def _send_verification_invite_fallback_channel(
    member: discord.Member, *, notice_trigger: str
) -> Optional[str]:
    """
    If DM fails (e.g. Forbidden), post @mention + Verify in #verify-yourself, else server system channel.
    Returns channel name if posted, else None.
    """
    guild = member.guild
    text = (
        f"{member.mention}\n"
        "We couldn't **DM** you — allow direct messages from this server (**Settings → Privacy & Safety**), "
        "or tap **Verify now** below.\n\n"
        + VERIFY_DM_BODY
    )
    verify_ch = get_channel_by_name(guild, VERIFY_CHANNEL_NAME)
    for ch in (verify_ch, guild.system_channel):
        if ch and isinstance(ch, discord.TextChannel):
            try:
                await ch.send(text, view=VerifyView())
                logger.info(
                    "Verification fallback posted in #%s for member %s (%s)",
                    ch.name,
                    member.id,
                    notice_trigger,
                )
                return ch.name
            except discord.HTTPException as exc:
                logger.warning("Verification fallback: could not send to #%s: %s", ch.name, exc)
    return None


async def send_verification_required_notice(
    member: discord.Member, *, notice_trigger: str = "unspecified"
) -> None:
    """
    1) DM **Verify now** + email modal (preferred).
    2) On DM failure (Forbidden / HTTP), @mention + same button in #verify-yourself or system channel.

    DB: `verification_invite_dm_ok` true iff DM succeeded; `verification_invite_last_attempt_at` always updated.
    The 30-minute compliance loop calls this again when it strips managed roles — retries transient DM errors.
    Forbidden DMs keep failing; public fallback covers that. `on_ready` sweeps users with dm_ok=false past cooldown.

    notice_trigger: recorded in VERIFY_YOURSELF_TRIGGER_LOG JSONL on successful delivery.
    """
    if member_is_verification_exempt(member):
        return

    gid = member.guild.id

    try:
        await member.send(VERIFY_DM_BODY, view=VerifyView())
        logger.info("Verification notice DM sent to member %s (%s)", member.id, notice_trigger)
        await db.record_verification_invite_outcome(member.id, dm_ok=True, guild_id=gid)
        log_verification_notice_sent(
            member, notice_trigger=notice_trigger, delivery="dm"
        )
        return
    except discord.Forbidden:
        logger.warning(
            "Verification notice: cannot DM member %s — trying public channel fallback (Privacy & Safety → allow DMs).",
            member.id,
        )
    except discord.HTTPException as exc:
        logger.warning("Verification notice: DM failed for %s: %s — trying channel fallback", member.id, exc)

    ch_name = await _send_verification_invite_fallback_channel(member, notice_trigger=notice_trigger)
    await db.record_verification_invite_outcome(member.id, dm_ok=False, guild_id=gid)
    if ch_name:
        log_verification_notice_sent(
            member,
            notice_trigger=notice_trigger,
            delivery="channel_fallback",
            fallback_channel=ch_name,
        )
    else:
        logger.error(
            "Verification: DM and channel fallback both failed for member %s — user may need admin help.",
            member.id,
        )


async def retry_verification_invites_after_reconnect(guild: discord.Guild) -> None:
    """
    After bot (re)connect, re-try DM for users who never got dm_ok (e.g. transient outage).
    Cooldown from last attempt uses VERIFICATION_DM_RETRY_COOLDOWN_MINUTES to avoid spam with on_ready repeats.
    """
    lock = _verification_invite_retry_lock_get()
    async with lock:
        await asyncio.sleep(35)
        try:
            rows = await db.list_discord_user_ids_pending_invite_dm_retry(
                str(guild.id), SETTINGS.verification_dm_retry_cooldown_minutes
            )
        except Exception:
            logger.exception("verification invite DM retry: query failed")
            return
        for row in rows:
            uid_str = row["discord_user_id"]
            try:
                uid = int(uid_str)
            except (TypeError, ValueError):
                continue
            member = guild.get_member(uid)
            if member is None or member.bot:
                continue
            if member_is_verification_exempt(member):
                continue
            rec = await db.get_user(uid)
            if rec and rec.get("access_revoked"):
                continue
            if rec and member_db_verified(rec):
                continue
            await send_verification_required_notice(member, notice_trigger="on_ready_dm_retry")
            await asyncio.sleep(0)


async def apply_access_revoke_in_discord(
    guild: discord.Guild, discord_user_id: int, reason: str
) -> bool:
    """
    Hard revoke: gate member and strip managed access roles. Updates DB via apply_revoke_completed.
    If user is not in the guild, DB is still cleared so the flag does not retry forever.
    """
    try:
        uid = int(discord_user_id)
    except (TypeError, ValueError):
        return False

    member = guild.get_member(uid)
    if member is None:
        try:
            member = await guild.fetch_member(uid)
        except discord.NotFound:
            logger.info("Revoke: user %s not in guild; clearing DB row only", uid)
            await db.apply_revoke_completed(uid)
            return True
        except Exception as exc:
            logger.warning("Revoke: could not fetch member %s: %s", uid, exc)
            return False

    try:
        await revoke_member_access(member, reason)
    except Exception as exc:
        logger.exception("Revoke: revoke_member_access failed for %s: %s", uid, exc)
        return False

    await db.apply_revoke_completed(uid)
    return True


# ============================================================
# Verification UI
# ============================================================
def _interaction_use_ephemeral(interaction: discord.Interaction) -> bool:
    """Ephemeral responses are only valid in guild channels."""
    return interaction.guild is not None


async def _guild_and_member_for_verify(
    interaction: discord.Interaction,
) -> Tuple[Optional[discord.Guild], Optional[discord.Member], Optional[str]]:
    """
    Resolve target guild (GUILD_ID) and Member for role updates.
    In DMs, interaction.user is User — fetch Member from the configured guild.
    Returns (guild, member, user_error_message).
    """
    u = interaction.user
    if interaction.guild is not None and isinstance(u, discord.Member):
        return interaction.guild, u, None
    g = bot.get_guild(SETTINGS.guild_id)
    if g is None:
        return None, None, "Bot cannot reach the server right now. Try again later or contact an admin."
    m = g.get_member(u.id)
    if m is None:
        try:
            m = await g.fetch_member(u.id)
        except discord.NotFound:
            return None, None, (
                "You must **join the server** first. After joining, open this DM again and tap **Verify now**."
            )
        except discord.HTTPException:
            return None, None, "Could not load your member profile. Try again in a moment."
    return g, m, None


class VerifyModal(discord.ui.Modal, title="Discord Access Verification"):
    email = discord.ui.TextInput(
        label="Deccan-associated mail address",
        placeholder="Your Deccan-associated email as on your allocation",
        required=True,
        max_length=120,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        guild, member, err = await _guild_and_member_for_verify(interaction)
        ephem = _interaction_use_ephemeral(interaction)
        if err:
            await interaction.response.send_message(err, ephemeral=ephem)
            return

        # Defer immediately: DB + role work must not block the initial interaction (3s limit → 10062).
        try:
            await interaction.response.defer(ephemeral=ephem)
        except discord.NotFound:
            logger.warning(
                "Verify modal: interaction expired before defer (10062) — try again after heavy server load."
            )
            return

        assert guild is not None and member is not None

        if member_is_verification_exempt(member):
            await interaction.followup.send(
                "Your role does not require verification.",
                ephemeral=ephem,
            )
            return

        record = await db.get_user(member.id)
        if record and record.get("access_revoked"):
            await interaction.followup.send(
                "Your access is being revoked or was revoked. Wait a moment or contact an admin.",
                ephemeral=ephem,
            )
            return
        if record and member_db_verified(record):
            await interaction.followup.send(
                "You are already verified (status is VERIFIED). No action needed.",
                ephemeral=ephem,
            )
            return

        email = str(self.email.value).strip()

        matched, row, message = await db.find_allocation_match(email=email)
        if not matched or not row:
            await db.mark_failed_attempt(member.id, message)
            await gate_member(member, "Verification failed")
            await interaction.followup.send(
                f"Verification failed: {message}",
                ephemeral=ephem,
            )
            return

        try:
            tokens_logged, assigned_roles = await finalize_verified_member(
                member,
                source_row=row,
                typed_email=email,
            )
        except Exception:
            logger.exception("finalize_verified_member failed for user %s", member.id)
            await interaction.followup.send(
                "Verification could not complete due to a server error. Please try again or contact an admin.",
                ephemeral=ephem,
            )
            return

        token_text = ", ".join(tokens_logged) if tokens_logged else "None (empty or unverifiable allocation)"
        role_text = ", ".join(assigned_roles) if assigned_roles else "No matching managed access roles on server (check allocations.projects, MANAGED_ACCESS_ROLE_NAMES, aliases, and Discord role names)"
        await interaction.followup.send(
            f"Verification successful.\n"
            f"Discord user ID (stored): `{member.id}`\n"
            f"Role tokens (from allocations.projects): {token_text}\n"
            f"Roles assigned on server: {role_text}",
            ephemeral=ephem,
        )
        canon = str(row.get("email") or "").strip()
        await send_status_message(
            guild,
            f"✅ Verified: {member.mention} | allocation_email={canon} | roles: {role_text}",
        )


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify now", style=discord.ButtonStyle.success, custom_id="verify_now_button")
    async def verify_now(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        ephem = _interaction_use_ephemeral(interaction)
        _guild, member, err = await _guild_and_member_for_verify(interaction)
        if err:
            await interaction.response.send_message(err, ephemeral=ephem)
            return
        assert member is not None

        if member_is_verification_exempt(member):
            await interaction.response.send_message(
                "Your role does not require verification.",
                ephemeral=ephem,
            )
            return

        # Open the modal immediately (no DB await first). Pre-checks run in VerifyModal.on_submit — avoids
        # 10062 when a long compliance audit delays this handler past Discord's 3s interaction window.
        try:
            await interaction.response.send_modal(VerifyModal())
        except discord.NotFound:
            logger.warning(
                "Verify button: interaction expired before modal (10062) — server may be busy; try again."
            )


async def ensure_verify_panel_in_channel(guild: discord.Guild) -> None:
    """
    (Disabled) Was: post a Verify panel in #verify-yourself. Invites are sent by DM only; re-enable by restoring
    the implementation from git history if you want an in-server panel again.
    """
    return


async def ensure_verify_channel_permissions(guild: discord.Guild) -> None:
    """
    (Disabled) Was: auto-set #verify-yourself overwrites. Configure that channel manually if you still use it.
    """
    return


# ============================================================
# Events
# ============================================================
@bot.event
async def on_ready() -> None:
    logger.info("Logged in as %s (%s)", bot.user, getattr(bot.user, "id", None))
    guild = bot.get_guild(SETTINGS.guild_id)
    if not guild:
        logger.error("Guild %s not found. Check GUILD_ID.", SETTINGS.guild_id)
        return

    await ensure_roles_exist(guild)
    # DM-only verification: no auto #verify-yourself panel or permission edits (see ensure_* stubs).
    # await ensure_verify_channel_permissions(guild)
    # await ensure_verify_panel_in_channel(guild)

    if not timeout_cleanup_loop.is_running():
        timeout_cleanup_loop.start()

    if not revoke_poll_loop.is_running():
        revoke_poll_loop.start()

    if not verification_compliance_loop.is_running():
        verification_compliance_loop.start()

    if SETTINGS.audit_on_startup:
        asyncio.create_task(run_full_verification_compliance_audit(guild, initial_delay=True))

    asyncio.create_task(retry_verification_invites_after_reconnect(guild))

    logger.info("Bot is ready")


@bot.event
async def setup_hook() -> None:
    await db.connect()
    await db.load_role_config()
    logger.info("Allocation data is read from PostgreSQL table `allocations`.")
    # Persistent views: register once per process (on_ready can run again on reconnect).
    bot.add_view(VerifyView())
    bot.add_view(AdminPanelView())


@bot.event
async def on_member_join(member: discord.Member) -> None:
    if member.guild.id != SETTINGS.guild_id:
        return
    if member.bot:
        return

    await db.touch_user(member.guild.id, member)

    record = await db.get_user(member.id)
    if record and record.get("access_revoked"):
        await revoke_member_access(member, "Access revoked (pending or active)")
        logger.info("Member %s has access_revoked flag; kept in gate", member)
        return

    if member_is_verification_exempt(member):
        await resync_verified_member_roles(member, record, "New member: verification exempt role")
        logger.info("Member %s exempt from verification (staff role); marked exempt in DB", member.id)
        return

    if record and member_db_verified(record):
        logger.info("Member %s already verified; resyncing roles from allocations / DB", member)
        await resync_verified_member_roles(member, record, "Previously verified user rejoined")
        return

    try:
        await revoke_member_access(member, "New member: verify before access roles")
    except discord.Forbidden:
        logger.error(
            "Join gate: cannot remove roles for %s — move the bot role above BB_Access/BB-Access and grant Manage Roles.",
            member.id,
        )
    leftover = member_access_role_names(member)
    if leftover:
        logger.error(
            "Join gate: %s still has access roles %s after strip — hierarchy, permissions, or role naming.",
            member.id,
            leftover,
        )
    logger.info("Member joined and held until verify: %s", member)
    await send_verification_required_notice(member, notice_trigger="member_join")


# ============================================================
# Background jobs & audit
# ============================================================
async def run_full_verification_compliance_audit(
    guild: discord.Guild,
    *,
    announce: bool = True,
    initial_delay: bool = True,
) -> None:
    """
    Every human member: match Discord to DB.
    Not verified (or no record) → strip managed access roles, gate; if they had access roles, DM verify invite.
    announce: if False, status channel is only notified when someone was revoked or stripped+notified (less spam).
    initial_delay: brief pause before first audit (startup only).
    """
    async with _compliance_audit_lock:
        if initial_delay:
            await asyncio.sleep(2)
        logger.info("Starting full verification compliance audit for guild %s", guild.id)
        verified_cleared = revoked_n = stripped_notice = 0
        try:
            for member in guild.members:
                if member.bot:
                    continue
                record = await db.get_user(member.id)
                if record and record.get("access_revoked"):
                    await revoke_member_access(member, "Compliance audit: access_revoked")
                    revoked_n += 1
                    continue
                if member_is_verification_exempt(member):
                    await resync_verified_member_roles(member, record, "Compliance audit: exempt role")
                    verified_cleared += 1
                    continue
                if record and member_db_verified(record):
                    await resync_verified_member_roles(member, record, "Compliance audit: verified")
                    verified_cleared += 1
                    continue
                had = member_access_role_names(member)
                await revoke_member_access(member, "Compliance audit: not verified")
                if had:
                    await send_verification_required_notice(
                        member, notice_trigger="compliance_audit"
                    )
                    stripped_notice += 1
                # Yield so gateway/interaction handlers (e.g. Verify button) are not starved during long audits.
                await asyncio.sleep(0)
            if announce or revoked_n > 0 or stripped_notice > 0:
                await send_status_message(
                    guild,
                    f"✅ Compliance audit: verified gate cleared={verified_cleared}, revoked={revoked_n}, "
                    f"unverified stripped+notified={stripped_notice}.",
                )
            else:
                logger.debug(
                    "Compliance audit (quiet): verified=%s, no revokes/strips to announce",
                    verified_cleared,
                )
        except Exception as exc:
            logger.exception("Compliance audit failed: %s", exc)
            await send_status_message(guild, f"⚠️ Compliance audit failed: {exc}")


async def sync_verification_roles_for_scoped_audit(
    member: discord.Member, record: Optional[Any], reason: str
) -> str:
    """
    Scoped audit (members with any managed access role): same verify-first rules.
    - access_revoked → hard revoke
    - verified in DB → clear gate only
    - else → strip managed access roles, gate, DM verify invite if they had access
    """
    if record and record.get("access_revoked"):
        await revoke_member_access(member, reason)
        return "revoked"
    if member_is_verification_exempt(member):
        await resync_verified_member_roles(member, record, reason)
        return "verified"
    if record and member_db_verified(record):
        await resync_verified_member_roles(member, record, reason)
        return "verified"
    had = member_access_role_names(member)
    await revoke_member_access(member, reason)
    if had:
        await send_verification_required_notice(member, notice_trigger=reason)
    return "gated"


@tasks.loop(minutes=1)
async def timeout_cleanup_loop() -> None:
    guild = bot.get_guild(SETTINGS.guild_id)
    if not guild:
        return

    stale_users = await db.get_stale_unverified_users(SETTINGS.verification_timeout_hours)
    for row in stale_users:
        uid_str = row["discord_user_id"]
        try:
            uid = int(uid_str)
        except (TypeError, ValueError):
            continue

        member = guild.get_member(uid)
        if member is None:
            try:
                member = await guild.fetch_member(uid)
            except discord.NotFound:
                await db.mark_timeout_removed(uid, "User not in server at timeout cleanup")
                continue
            except Exception as exc:
                logger.warning("Could not fetch member %s: %s", uid, exc)
                continue

        if member_is_verification_exempt(member):
            await db.mark_verification_exempt(guild.id, member)
            continue

        try:
            await revoke_member_access(
                member,
                f"Verification timeout ({SETTINGS.verification_timeout_hours}h)",
            )
            await db.mark_timeout_removed(
                uid,
                f"Timed out after {SETTINGS.verification_timeout_hours}h without verification (access removed)",
            )
            await send_status_message(
                guild,
                f"⏱️ Timeout: {member.mention} — verification window expired; managed access roles removed, still gated.",
            )
        except Exception as exc:
            logger.exception("Timeout cleanup failed for %s: %s", uid, exc)


@timeout_cleanup_loop.before_loop
async def before_timeout_cleanup_loop() -> None:
    await bot.wait_until_ready()


async def inactive_allocation_sweep(guild: discord.Guild) -> None:
    """Strip managed roles from verified members whose allocation.active=False and log to user_removal."""
    assert db.pool is not None
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT duv.discord_user_id, duv.email, duv.discord_username
            FROM discord_user_verification duv
            JOIN allocations a ON a.email = duv.email
            WHERE duv.guild_id = $1
              AND duv.status = 'VERIFIED'
              AND a.active = FALSE
            """,
            str(SETTINGS.guild_id),
        )
    for row in rows:
        try:
            uid = int(row["discord_user_id"])
        except (TypeError, ValueError):
            continue
        member = guild.get_member(uid)
        if member is None:
            try:
                member = await guild.fetch_member(uid)
            except discord.NotFound:
                await db.insert_user_removal(
                    discord_user_id=uid,
                    email=row["email"],
                    discord_username=row["discord_username"],
                    reason="allocation.active=False (member not in guild)",
                    removed_by="system",
                )
                await db.apply_revoke_completed(uid)
                continue
            except Exception as exc:
                logger.warning("inactive_allocation_sweep: fetch %s failed: %s", uid, exc)
                continue
        await _strip_inactive_allocation_member(
            member,
            email=row["email"] or "",
            reason="allocation.active=False (compliance sweep)",
            removed_by="system",
        )
        await asyncio.sleep(0)


@tasks.loop(minutes=30)
async def verification_compliance_loop() -> None:
    """Re-run full verify-first compliance pass every 30 minutes."""
    guild = bot.get_guild(SETTINGS.guild_id)
    if not guild:
        return
    await run_full_verification_compliance_audit(guild, announce=False, initial_delay=False)
    await inactive_allocation_sweep(guild)


@verification_compliance_loop.before_loop
async def before_verification_compliance_loop() -> None:
    await bot.wait_until_ready()


@tasks.loop(minutes=1)
async def revoke_poll_loop() -> None:
    """Apply Discord revokes when access_revoked=true is set in Supabase / DB."""
    guild = bot.get_guild(SETTINGS.guild_id)
    if not guild:
        return

    rows = await db.get_pending_revoke_users()
    for row in rows:
        uid_str = row["discord_user_id"]
        try:
            uid = int(uid_str)
        except (TypeError, ValueError):
            continue

        ok = await apply_access_revoke_in_discord(
            guild,
            uid,
            "Access revoked (database flag)",
        )
        if ok:
            await send_status_message(
                guild,
                f"⛔ Access revoked for Discord user id `{uid}` (database request).",
            )


@revoke_poll_loop.before_loop
async def before_revoke_poll_loop() -> None:
    await bot.wait_until_ready()


# ============================================================
# Health (e.g. Render)
# ============================================================
async def healthz(_request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "bot_user": str(bot.user) if bot.user else None})


async def readyz(_request: web.Request) -> web.Response:
    ready = bot.is_ready()
    return web.json_response({"ready": ready}, status=200 if ready else 503)


async def start_health_server() -> None:
    app = web.Application()
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/readyz", readyz)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logger.info("Health server listening on 0.0.0.0:%s", PORT)


# ============================================================
# Admin commands
# ============================================================
def is_admin(member: discord.Member) -> bool:
    return any(r.name == SETTINGS.admin_role_name for r in member.roles)


@bot.command(name="helpme")
async def helpme_command(ctx: commands.Context) -> None:
    text = (
        "**Verify first:** managed access roles (see `MANAGED_ACCESS_ROLE_NAMES` in bot_verifier.py) are removed until you complete verification. After verify, roles follow **`allocations.projects`** for your allocation (whitelist + optional aliases in code).\n"
        + VERIFY_REQUIREMENTS_SHORT
        + "\n"
        "Use **Verify now** below in this channel, or check your **DMs from this bot** if you were prompted there.\n"
        "DB **status** = VERIFIED | NOT_VERIFIED (no Discord Verified role). Deny **Unverified** on gated categories.\n"
        "`!reset_verification` — strips managed access roles and resets DB; you must verify again. Admins: `!reset_verification @user`.\n"
        "`!revoke_access @user` — admin: revoke + gate.\n"
        "`!kick` / `!ban` — sets `allocations.status` REVOKE/BAN when allocation `email` is stored for the user.\n"
        "Admins: `!audit_bluebird` — compliance for members with any role in **MANAGED_ACCESS_ROLE_NAMES** (see bot_verifier.py)."
    )
    view = VerifyView() if ctx.guild else None
    await ctx.reply(text, view=view)


@bot.command(name="reset_verification")
async def reset_verification_command(ctx: commands.Context, member: Optional[discord.Member] = None) -> None:
    if not isinstance(ctx.author, discord.Member):
        await ctx.reply("Run this in the server.")
        return
    target = member or ctx.author
    if target.id != ctx.author.id and not is_admin(ctx.author):
        await ctx.reply("Only admins can reset other members.")
        return
    await db.reset_user(target.id)
    await revoke_member_access(target, "Verification reset")
    await send_verification_required_notice(target, notice_trigger="reset_verification")
    reset_view = VerifyView() if ctx.guild else None
    await ctx.reply(
        f"Verification reset for {target.mention}. Managed access roles removed until they verify again.",
        view=reset_view,
    )


@bot.command(name="audit_bluebird")
async def audit_bluebird_command(ctx: commands.Context) -> None:
    """Compliance pass: members holding any role in MANAGED_ACCESS_ROLE_NAMES."""
    if not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
        await ctx.reply("You are not authorized.")
        return
    if not ctx.guild:
        await ctx.reply("Run this in the server.")
        return

    targets = members_with_any_managed_access_role(ctx.guild)
    if not targets:
        await ctx.reply("No members hold any role listed in **MANAGED_ACCESS_ROLE_NAMES** (see bot_verifier.py).")
        return

    checked = gated = verified = revoked = 0
    for member in targets:
        checked += 1
        record = await db.get_user(member.id)
        outcome = await sync_verification_roles_for_scoped_audit(
            member,
            record,
            "Bluebird audit",
        )
        if outcome == "revoked":
            revoked += 1
        elif outcome == "verified":
            verified += 1
        else:
            gated += 1

    await ctx.reply(
        f"Bluebird audit done. checked={checked}, verified={verified}, gated={gated}, revoked={revoked}."
    )


@bot.command(name="revoke_access")
async def revoke_access_command(ctx: commands.Context, member: Optional[discord.Member] = None) -> None:
    if not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
        await ctx.reply("You are not authorized.")
        return
    if not ctx.guild or member is None:
        await ctx.reply("Usage: `!revoke_access @member`")
        return
    ok = await apply_access_revoke_in_discord(
        ctx.guild,
        member.id,
        f"Admin revoke by {ctx.author}",
    )
    if ok:
        await db.log_admin_action(
            ctx.author,
            "revoke_access",
            target_discord_id=member.id,
            details={"reason": f"Admin revoke by {ctx.author}"},
        )
        await send_verification_required_notice(member, notice_trigger="revoke_access")
        await ctx.reply(
            f"Access revoked for {member.mention}. They can use **Verify** again after re-approval.",
            view=VerifyView(),
        )
    else:
        await ctx.reply(
            f"Could not revoke in Discord for {member.mention}; DB flag may still be set — check logs."
        )


@bot.command(name="kick")
async def kick_command(ctx: commands.Context, member: Optional[discord.Member] = None, *, reason: str = "") -> None:
    """Remove member from server; they can rejoin with a new invite."""
    if not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
        await ctx.reply("You are not authorized.")
        return
    if not ctx.guild or member is None:
        await ctx.reply("Usage: `!kick @member` (optional reason after the mention)")
        return
    if member.bot:
        await ctx.reply("Cannot kick bots.")
        return
    if member.id == ctx.author.id:
        await ctx.reply("You cannot kick yourself.")
        return
    if ctx.guild.owner_id == member.id:
        await ctx.reply("Cannot kick the server owner.")
        return
    me = ctx.guild.me
    if me and member.top_role >= me.top_role and member.id != me.id:
        await ctx.reply("That member is above or equal to the bot's role — move the bot role higher.")
        return

    kick_reason = reason.strip() or "Kicked by admin"
    record = await db.get_user(member.id)
    alloc_email = (record.get("email") or "").strip() if record else ""

    try:
        await member.kick(reason=kick_reason[:500])
    except discord.Forbidden:
        await ctx.reply("Missing **Kick Members** or role hierarchy is blocking this.")
        return
    except discord.HTTPException as exc:
        await ctx.reply(f"Kick failed: {exc}")
        return

    alloc_note = ""
    if alloc_email:
        ok = await db.set_allocation_status_by_email(alloc_email, "REVOKE")
        alloc_note = f" `allocations.status` → **REVOKE** (`{alloc_email}`)." if ok else (
            f" No `allocations` row for email `{alloc_email}`."
        )
    else:
        alloc_note = " No allocation `email` in `discord_user_verification` — allocation row not updated."

    await db.log_admin_action(
        ctx.author,
        "kick",
        target_discord_id=member.id,
        target_email=alloc_email or None,
        details={"reason": kick_reason, "alloc_note": alloc_note.strip()},
    )
    logger.info("Kick: %s by %s (%s)", member.id, ctx.author.id, kick_reason)
    await ctx.reply(f"Kicked **{member}** ({kick_reason}).{alloc_note}")


@bot.command(name="ban")
async def ban_command(ctx: commands.Context, member: Optional[discord.Member] = None, *, reason: str = "") -> None:
    """Ban member from server; mark allocations.status BAN (does not delete allocation rows)."""
    if not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
        await ctx.reply("You are not authorized.")
        return
    if not ctx.guild or member is None:
        await ctx.reply("Usage: `!ban @member` (optional reason after the mention)")
        return
    if member.bot:
        await ctx.reply("Cannot ban bots.")
        return
    if member.id == ctx.author.id:
        await ctx.reply("You cannot ban yourself.")
        return
    if ctx.guild.owner_id == member.id:
        await ctx.reply("Cannot ban the server owner.")
        return
    me = ctx.guild.me
    if me and member.top_role >= me.top_role and member.id != me.id:
        await ctx.reply("That member is above or equal to the bot's role — move the bot role higher.")
        return

    ban_reason = reason.strip() or "Banned by admin"
    uid = member.id
    record = await db.get_user(member.id)
    alloc_email = (record.get("email") or "").strip() if record else ""

    try:
        await member.ban(reason=ban_reason[:500], delete_message_days=0)
    except discord.Forbidden:
        await ctx.reply("Missing **Ban Members** or role hierarchy is blocking this.")
        return
    except discord.HTTPException as exc:
        await ctx.reply(f"Ban failed: {exc}")
        return

    alloc_note = ""
    if alloc_email:
        ok = await db.set_allocation_status_by_email(alloc_email, "BAN")
        alloc_note = f" `allocations.status` → **BAN** (`{alloc_email}`)." if ok else (
            f" No `allocations` row for email `{alloc_email}`."
        )
    else:
        alloc_note = " No allocation `email` in `discord_user_verification` — allocation row not updated."

    await db.log_admin_action(
        ctx.author,
        "ban",
        target_discord_id=uid,
        target_email=alloc_email or None,
        details={"reason": ban_reason, "alloc_note": alloc_note.strip()},
    )
    logger.info("Ban: %s by %s (%s)", uid, ctx.author.id, ban_reason)
    await ctx.reply(f"Banned **{member}** ({ban_reason}).{alloc_note}")


# ============================================================
# Admin Management Panel
# ============================================================

async def _load_admin_panel_id() -> Optional[int]:
    try:
        val = await db.get_setting("admin_panel_message_id")
        return int(val) if val else None
    except (TypeError, ValueError):
        return None


async def _save_admin_panel_id(message_id: int) -> None:
    await db.set_setting("admin_panel_message_id", str(message_id))


def _is_panel_authorized(interaction: discord.Interaction) -> bool:
    if not isinstance(interaction.user, discord.Member):
        return False
    allowed = {SETTINGS.admin_role_name, SUPPORT_ROLE_NAME}
    return any(r.name in allowed for r in interaction.user.roles)


def _panel_embed() -> discord.Embed:
    embed = discord.Embed(
        title="🛠️ Admin Management Panel",
        colour=discord.Colour.blurple(),
        timestamp=datetime.now(UTC),
    )
    embed.add_field(
        name="👤 User Management",
        value=(
            "➕ **Add User to Role** — Add email + role to allocations\n"
            "➖ **Remove User from Role** — Remove a role token from an allocation\n"
            "🔄 **Reset / Re-verify User** — Force a user to re-verify\n"
            "✏️ **Edit Allocation** — Update projects / active / status"
        ),
        inline=False,
    )
    embed.add_field(
        name="📦 Bulk Operations",
        value=(
            "📋 **Bulk Add Users** — Add multiple users at once (paste or CSV)\n"
            "✅ **Bulk Assign Role** — Add a managed role to multiple users\n"
            "🗑️ **Bulk Remove Role** — Strip a managed role from multiple users\n"
            "🚫 **Bulk Server Remove** — Kick multiple users from the server"
        ),
        inline=False,
    )
    embed.add_field(
        name="🔍 Visibility & Config",
        value=(
            "👁️ **View Members by Role** — List all verified users under a role\n"
            "🔎 **User Status** — Check a user's DB record, verification state & allocation\n"
            "⚙️ **Role Config** — View / edit managed and exempt role lists"
        ),
        inline=False,
    )
    embed.set_footer(text=f"Responses are private · Access: {SETTINGS.admin_role_name} & {SUPPORT_ROLE_NAME}")
    return embed


# ── Add User ──────────────────────────────────────────────────────────────────

class AddUserModal(discord.ui.Modal, title="Add User to Role"):
    email = discord.ui.TextInput(
        label="Email address",
        placeholder="user@example.com",
        required=True,
        max_length=200,
    )
    projects = discord.ui.TextInput(
        label="Role tokens (comma-separated)",
        placeholder="BB_Access,maitrix-coders",
        required=True,
        max_length=500,
    )
    full_name = discord.ui.TextInput(
        label="Full name (optional)",
        required=False,
        max_length=200,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        email_val = self.email.value.strip().lower()
        projects_val = self.projects.value.strip()
        full_name_val = (self.full_name.value or "").strip() or None

        tokens = [t.strip() for t in re.split(r"[,;|/]+", projects_val) if t.strip()]
        invalid = [t for t in tokens if t not in SETTINGS.managed_access_role_names]
        if invalid:
            valid_list = ", ".join(sorted(SETTINGS.managed_access_role_names))
            await interaction.followup.send(
                f"Invalid role tokens: **{', '.join(invalid)}**\nValid: `{valid_list}`",
                ephemeral=True,
            )
            return

        projects_str = ",".join(tokens)
        assert db.pool is not None
        async with db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO allocations (email, full_name, projects, active, status, updated_at)
                VALUES ($1, $2, $3, TRUE, 'ACTIVE', NOW())
                ON CONFLICT (email) DO UPDATE SET
                    full_name = COALESCE(EXCLUDED.full_name, allocations.full_name),
                    projects = EXCLUDED.projects,
                    active = TRUE,
                    status = 'ACTIVE',
                    updated_at = NOW()
                """,
                email_val, full_name_val, _projects_to_db(tokens),
            )

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        assigned_note = ""
        if guild:
            assert db.pool is not None
            async with db.pool.acquire() as conn:
                rec = await conn.fetchrow(
                    "SELECT discord_user_id FROM discord_user_verification WHERE email = $1 AND status = 'VERIFIED'",
                    email_val,
                )
            if rec:
                uid = int(rec["discord_user_id"])
                try:
                    member = guild.get_member(uid) or await guild.fetch_member(uid)
                    if member:
                        alloc = await db.fetch_allocation_by_email(email_val)
                        if alloc:
                            t_list = get_managed_role_tokens_for_verified_allocation(alloc)
                            allowed = allowed_managed_access_names_from_tokens(guild, t_list)
                            assigned = await sync_managed_access_roles(
                                member, allowed, "Admin panel: add user"
                            )
                            assigned_note = f"\nRoles applied to {member.mention}: `{', '.join(assigned) or 'none'}`."
                except discord.NotFound:
                    pass

        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "add_user_to_role",
                target_email=email_val,
                details={"projects": projects_str, "roles_assigned": assigned_note.strip() or "none"},
            )

        await interaction.followup.send(
            f"Allocation saved: **{email_val}** → `{projects_str}`.{assigned_note}",
            ephemeral=True,
        )


# ── Remove User from Role ─────────────────────────────────────────────────────

class RemoveRoleEmailModal(discord.ui.Modal, title="Remove User from Role"):
    email = discord.ui.TextInput(
        label="Email address",
        placeholder="user@example.com",
        required=True,
        max_length=200,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        email_val = self.email.value.strip().lower()
        alloc = await db.fetch_allocation_by_email(email_val)
        if not alloc:
            await interaction.followup.send(f"No allocation found for `{email_val}`.", ephemeral=True)
            return
        tokens = split_projects_str(alloc.get("projects"))
        if not tokens:
            await interaction.followup.send(
                f"No roles currently assigned to `{email_val}`.", ephemeral=True
            )
            return
        await interaction.followup.send(
            f"Select a role to remove from **{email_val}**:",
            view=RemoveRoleSelectView(email_val, tokens),
            ephemeral=True,
        )


class RemoveRoleSelect(discord.ui.Select):
    def __init__(self, email: str, tokens: List[str]) -> None:
        self._email = email
        super().__init__(
            placeholder="Choose role to remove",
            options=[discord.SelectOption(label=t, value=t) for t in tokens[:25]],
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        token = self.values[0]
        await interaction.response.defer(ephemeral=True)

        alloc = await db.fetch_allocation_by_email(self._email)
        if not alloc:
            await interaction.followup.send("Allocation no longer found.", ephemeral=True)
            return
        new_tokens = [t for t in split_projects_str(alloc.get("projects")) if t != token]
        new_projects = ",".join(new_tokens)

        assert db.pool is not None
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE allocations SET projects = $1, updated_at = NOW() WHERE email = $2",
                _projects_to_db(new_tokens),
                self._email,
            )

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        stripped_note = ""
        if guild:
            async with db.pool.acquire() as conn:
                rec = await conn.fetchrow(
                    "SELECT discord_user_id FROM discord_user_verification WHERE email = $1",
                    self._email,
                )
            if rec:
                uid = int(rec["discord_user_id"])
                try:
                    member = guild.get_member(uid) or await guild.fetch_member(uid)
                    if member:
                        removed = await remove_role_if_present(
                            member, token, "Admin panel: remove role"
                        )
                        stripped_note = (
                            f"\nRole `{token}` stripped from {member.mention}."
                            if removed
                            else f"\n{member.mention} didn't have `{token}` in Discord."
                        )
                except discord.NotFound:
                    pass

        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "remove_user_from_role",
                target_email=self._email,
                details={"removed_token": token, "remaining_projects": new_projects},
            )

        remaining = f"`{new_projects}`" if new_projects else "_(none)_"
        await interaction.followup.send(
            f"Removed `{token}` from **{self._email}**. Remaining: {remaining}.{stripped_note}",
            ephemeral=True,
        )


class RemoveRoleSelectView(discord.ui.View):
    def __init__(self, email: str, tokens: List[str]) -> None:
        super().__init__(timeout=120)
        self.add_item(RemoveRoleSelect(email, tokens))


# ── View Members by Role ──────────────────────────────────────────────────────

class ViewByRoleSelect(discord.ui.Select):
    def __init__(self) -> None:
        options = [
            discord.SelectOption(label=r, value=r) for r in sorted(SETTINGS.managed_access_role_names)
        ]
        super().__init__(placeholder="Choose a role to view members", options=options[:25])

    async def callback(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        role_name = self.values[0]
        await interaction.response.defer(ephemeral=True)

        assert db.pool is not None
        async with db.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT duv.discord_user_id, duv.discord_username, duv.email, a.projects
                FROM discord_user_verification duv
                LEFT JOIN allocations a ON a.email = duv.email
                WHERE duv.guild_id = $1 AND duv.status = 'VERIFIED'
                ORDER BY duv.discord_username
                """,
                str(SETTINGS.guild_id),
            )

        matching = []
        for row in rows:
            tokens = split_projects_str(row["projects"])
            resolved = {PROJECT_ROLE_ALIASES.get(t, t) for t in tokens} | set(tokens)
            if role_name in resolved:
                matching.append(row)

        if not matching:
            await interaction.followup.send(
                f"No verified members found with role **{role_name}**.", ephemeral=True
            )
            return

        lines = [
            f"• <@{r['discord_user_id']}> `{r['discord_username'] or r['discord_user_id']}` — `{r['email'] or '—'}`"
            for r in matching[:50]
        ]
        truncated = f"\n_…and {len(matching) - 50} more_" if len(matching) > 50 else ""
        embed = discord.Embed(
            title=f"Members with role: {role_name}",
            description="\n".join(lines) + truncated,
            colour=discord.Colour.green(),
        )
        embed.set_footer(text=f"Total: {len(matching)}")
        await interaction.followup.send(embed=embed, ephemeral=True)


class ViewByRoleView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=120)
        self.add_item(ViewByRoleSelect())


# ── Edit Allocation ───────────────────────────────────────────────────────────

class EditAllocationEmailModal(discord.ui.Modal, title="Edit Allocation"):
    email = discord.ui.TextInput(
        label="Email address to edit",
        placeholder="user@example.com",
        required=True,
        max_length=200,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        email_val = self.email.value.strip().lower()
        alloc = await db.fetch_allocation_by_email(email_val)
        if not alloc:
            await interaction.followup.send(f"No allocation found for `{email_val}`.", ephemeral=True)
            return
        current_projects = alloc.get("projects") or ""
        current_active = "true" if alloc.get("active") else "false"
        current_status = alloc.get("status") or "ACTIVE"
        await interaction.followup.send(
            f"**Editing `{email_val}`:**\n"
            f"• Projects: `{current_projects}`\n"
            f"• Active: `{current_active}`\n"
            f"• Status: `{current_status}`\n\n"
            "Click **Edit** to make changes:",
            view=EditAllocationConfirmView(alloc),
            ephemeral=True,
        )


class EditAllocationFieldsModal(discord.ui.Modal, title="Edit Allocation Fields"):
    def __init__(self, alloc: Dict[str, Any]) -> None:
        super().__init__()
        self._email = str(alloc.get("email") or "").strip()
        self.projects_input = discord.ui.TextInput(
            label="Role tokens (comma-separated)",
            default=",".join(split_projects_str(alloc.get("projects"))),
            required=True,
            max_length=500,
        )
        self.active_input = discord.ui.TextInput(
            label="Active (true / false)",
            default="true" if alloc.get("active") else "false",
            required=True,
            max_length=10,
        )
        self.status_input = discord.ui.TextInput(
            label="Status (ACTIVE / REVOKE / BAN)",
            default=str(alloc.get("status") or "ACTIVE"),
            required=True,
            max_length=20,
        )
        self.add_item(self.projects_input)
        self.add_item(self.active_input)
        self.add_item(self.status_input)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        projects_val = self.projects_input.value.strip()
        active_val = self.active_input.value.strip().lower() in ("true", "1", "yes")
        status_val = self.status_input.value.strip().upper()

        if status_val not in ("ACTIVE", "REVOKE", "BAN"):
            await interaction.followup.send(
                "Status must be ACTIVE, REVOKE, or BAN.", ephemeral=True
            )
            return

        # Parse user-typed comma-sep string into canonical tokens for DB write.
        projects_tokens = split_projects_str(projects_val)
        projects_display = ",".join(projects_tokens)

        assert db.pool is not None
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE allocations SET projects=$1, active=$2, status=$3, updated_at=NOW() WHERE email=$4",
                _projects_to_db(projects_tokens),
                active_val,
                status_val,
                self._email,
            )

        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "edit_allocation",
                target_email=self._email,
                details={"projects": projects_display, "active": active_val, "status": status_val},
            )

        # Immediately strip roles when active is set to False
        strip_note = ""
        if not active_val:
            guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
            if guild:
                assert db.pool is not None
                async with db.pool.acquire() as conn:
                    rec = await conn.fetchrow(
                        "SELECT discord_user_id, discord_username FROM discord_user_verification "
                        "WHERE email = $1 AND status = 'VERIFIED'",
                        self._email,
                    )
                if rec:
                    removed_by = str(interaction.user.id) if interaction.user else "system"
                    try:
                        uid = int(rec["discord_user_id"])
                        member = guild.get_member(uid) or await guild.fetch_member(uid)
                        if member:
                            stripped = await _strip_inactive_allocation_member(
                                member,
                                email=self._email,
                                reason="allocation.active set to False by admin",
                                removed_by=removed_by,
                            )
                            strip_note = "\n• Managed roles **stripped** and logged to `user_removal`." if stripped else ""
                    except discord.NotFound:
                        await db.insert_user_removal(
                            discord_user_id=int(rec["discord_user_id"]),
                            email=self._email,
                            discord_username=rec["discord_username"],
                            reason="allocation.active set to False (member not in guild)",
                            removed_by=removed_by,
                        )
                        await db.apply_revoke_completed(int(rec["discord_user_id"]))
                        strip_note = "\n• Member not in guild — logged to `user_removal`."
                    except Exception as exc:
                        logger.warning("EditAllocation active=False strip failed for %s: %s", self._email, exc)

        await interaction.followup.send(
            f"Updated **{self._email}**:\n"
            f"• Projects: `{projects_display}`\n"
            f"• Active: `{active_val}`\n"
            f"• Status: `{status_val}`"
            + strip_note,
            ephemeral=True,
        )


class EditAllocationConfirmView(discord.ui.View):
    def __init__(self, alloc: Dict[str, Any]) -> None:
        super().__init__(timeout=120)
        self._alloc = alloc

    @discord.ui.button(label="Edit", style=discord.ButtonStyle.primary)
    async def edit_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(EditAllocationFieldsModal(self._alloc))


# ── Reset / Re-verify User ────────────────────────────────────────────────────

class ResetUserModal(discord.ui.Modal, title="Reset / Re-verify User"):
    user_input = discord.ui.TextInput(
        label="Username, display name, or user ID",
        placeholder="e.g. johndoe, John Doe, or 123456789012345678",
        required=True,
        max_length=200,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        if not guild:
            await interaction.response.send_message("Guild not found.", ephemeral=True)
            return

        target = await _resolve_member_by_query(guild, self.user_input.value)

        if target is None:
            await interaction.response.send_message(
                f"No member found matching **{discord.utils.escape_markdown(self.user_input.value.strip())}**. "
                "Try their exact username or paste their user ID.",
                ephemeral=True,
            )
            return

        if target.bot:
            await interaction.response.send_message("Cannot reset bots.", ephemeral=True)
            return

        await interaction.response.send_message(
            f"Reset verification for {target.mention} (`{target}`)? "
            "They will be re-gated and asked to verify again.",
            view=ResetConfirmView(target),
            ephemeral=True,
        )


class ResetConfirmView(discord.ui.View):
    def __init__(self, member: discord.Member) -> None:
        super().__init__(timeout=60)
        self._member = member

    @discord.ui.button(label="Confirm Reset", style=discord.ButtonStyle.danger)
    async def confirm(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        await db.reset_user(self._member.id)
        await revoke_member_access(self._member, "Admin panel: reset verification")
        await send_verification_required_notice(self._member, notice_trigger="admin_panel_reset")

        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "reset_user",
                target_discord_id=self._member.id,
                details={"discord_username": str(self._member)},
            )

        await interaction.followup.send(
            f"Verification reset for {self._member.mention}. They have been re-gated and notified.",
            ephemeral=True,
        )

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await interaction.response.send_message("Reset cancelled.", ephemeral=True)


# ── Bulk Add ──────────────────────────────────────────────────────────────────

class BulkAddPasteModal(discord.ui.Modal, title="Bulk Add Users"):
    content = discord.ui.TextInput(
        label="email,projects — one entry per line",
        placeholder="user@example.com,BB_Access\nother@example.com,maitrix-coders",
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=4000,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        await _process_bulk_add_text(interaction, self.content.value, source="paste")


class BulkAddChoiceView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=60)

    @discord.ui.button(label="Paste List", style=discord.ButtonStyle.primary)
    async def paste(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(BulkAddPasteModal())

    @discord.ui.button(label="Upload CSV", style=discord.ButtonStyle.secondary)
    async def upload_csv(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        channel = interaction.channel
        if not channel:
            await interaction.response.send_message("Cannot determine channel.", ephemeral=True)
            return
        await interaction.response.send_message(
            "Upload a `.csv` file with columns `email,projects` to **this channel** within **60 seconds**.\n"
            "A header row is optional. Example:\n```\nuser@example.com,BB_Access\nother@example.com,maitrix-coders\n```",
            ephemeral=True,
        )

        def check(m: discord.Message) -> bool:
            return (
                m.author.id == interaction.user.id
                and m.channel.id == channel.id  # type: ignore[union-attr]
                and bool(m.attachments)
            )

        try:
            msg = await bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await interaction.followup.send("Timed out. No file received.", ephemeral=True)
            return

        attachment = msg.attachments[0]
        if not attachment.filename.lower().endswith(".csv"):
            await interaction.followup.send("Please upload a `.csv` file.", ephemeral=True)
            return

        raw = await attachment.read()
        text = raw.decode("utf-8", errors="replace")
        await _process_bulk_add_text(interaction, text, source="csv")


async def _process_bulk_add_text(
    interaction: discord.Interaction, text: str, source: str
) -> None:
    import csv as csv_mod
    import io as io_mod

    guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
    reader = csv_mod.reader(io_mod.StringIO(text.strip()))
    added = updated = 0
    failed: List[str] = []

    assert db.pool is not None
    for row in reader:
        if not row:
            continue
        if row[0].strip().lower() in ("email", "e-mail"):
            continue
        if len(row) < 2:
            failed.append(f"`{row[0].strip()}` — missing projects column")
            continue
        email_val = row[0].strip().lower()
        projects_val = row[1].strip()
        if not email_val or "@" not in email_val:
            failed.append(f"`{row[0].strip()}` — invalid email")
            continue
        tokens = [t.strip() for t in re.split(r"[,;|/]+", projects_val) if t.strip()]
        bad = [t for t in tokens if t not in SETTINGS.managed_access_role_names]
        if bad:
            failed.append(f"`{email_val}` — invalid tokens: {', '.join(bad)}")
            continue
        try:
            async with db.pool.acquire() as conn:
                existing = await conn.fetchrow(
                    "SELECT email FROM allocations WHERE email = $1", email_val
                )
                await conn.execute(
                    """
                    INSERT INTO allocations (email, projects, active, status, updated_at)
                    VALUES ($1, $2, TRUE, 'ACTIVE', NOW())
                    ON CONFLICT (email) DO UPDATE SET
                        projects = EXCLUDED.projects,
                        active = TRUE,
                        status = 'ACTIVE',
                        updated_at = NOW()
                    """,
                    email_val,
                    _projects_to_db(tokens),
                )
            if existing:
                updated += 1
            else:
                added += 1
            if guild:
                async with db.pool.acquire() as conn:
                    rec = await conn.fetchrow(
                        "SELECT discord_user_id FROM discord_user_verification WHERE email = $1 AND status = 'VERIFIED'",
                        email_val,
                    )
                if rec:
                    uid = int(rec["discord_user_id"])
                    try:
                        member = guild.get_member(uid) or await guild.fetch_member(uid)
                        if member:
                            alloc = await db.fetch_allocation_by_email(email_val)
                            if alloc:
                                t_list = get_managed_role_tokens_for_verified_allocation(alloc)
                                allowed_r = allowed_managed_access_names_from_tokens(guild, t_list)
                                await sync_managed_access_roles(
                                    member, allowed_r, "Admin panel: bulk add"
                                )
                    except discord.NotFound:
                        pass
        except Exception as exc:
            logger.exception("Bulk add error for %s", email_val)
            failed.append(f"`{email_val}` — error: {exc}")

    if isinstance(interaction.user, discord.Member):
        await db.log_admin_action(
            interaction.user,
            "bulk_add",
            details={"source": source, "added": added, "updated": updated, "failed_count": len(failed)},
        )

    summary = (
        f"**Bulk add complete** (via {source})\n"
        f"✅ New: {added} | 🔄 Updated: {updated} | ❌ Failed: {len(failed)}"
    )
    if failed:
        fail_lines = "\n".join(failed[:20])
        if len(failed) > 20:
            fail_lines += f"\n…and {len(failed) - 20} more"
        summary += f"\n\n**Failures:**\n{fail_lines}"
    await interaction.followup.send(summary, ephemeral=True)


# ── Bulk Assign Role ──────────────────────────────────────────────────────────

class BulkAssignRoleModal(discord.ui.Modal, title="Bulk Assign Role"):
    users_input = discord.ui.TextInput(
        label="Discord usernames or IDs (one per line)",
        style=discord.TextStyle.paragraph,
        placeholder="johndoe\n123456789012345678\nJane Doe",
        required=True,
        max_length=4000,
    )
    role_token = discord.ui.TextInput(
        label="Role token to assign",
        placeholder="BB_Access",
        required=True,
        max_length=100,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        token = self.role_token.value.strip()
        if token not in SETTINGS.managed_access_role_names:
            valid = ", ".join(sorted(SETTINGS.managed_access_role_names))
            await interaction.followup.send(
                f"Invalid role token `{token}`.\nValid options: `{valid}`", ephemeral=True
            )
            return

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        if not guild:
            await interaction.followup.send("Guild not found.", ephemeral=True)
            return

        lines = [l.strip() for l in self.users_input.value.splitlines() if l.strip()]
        ok: List[str] = []
        no_alloc: List[str] = []
        not_found: List[str] = []

        for line in lines:
            member = await _resolve_member_by_query(guild, line)
            if member is None:
                not_found.append(line)
                continue
            rec = await db.get_user(member.id)
            email = (rec.get("email") or "").strip() if rec else ""
            if not email:
                no_alloc.append(str(member))
                continue
            try:
                assert db.pool is not None
                async with db.pool.acquire() as conn:
                    alloc = await conn.fetchrow("SELECT projects FROM allocations WHERE email = $1", email)
                    if alloc is None:
                        no_alloc.append(str(member))
                        continue
                    existing_tokens = split_projects_str(alloc["projects"])
                    if token not in existing_tokens:
                        existing_tokens.append(token)
                    await conn.execute(
                        "UPDATE allocations SET projects=$1, updated_at=NOW() WHERE email=$2",
                        _projects_to_db(existing_tokens),
                        email,
                    )
                allowed = allowed_managed_access_names_from_tokens(guild, existing_tokens)
                await sync_managed_access_roles(member, allowed, "Admin panel: bulk assign role")
                if isinstance(interaction.user, discord.Member):
                    await db.log_admin_action(
                        interaction.user,
                        "bulk_role_allocation",
                        target_discord_id=member.id,
                        target_email=email,
                        details={"role_token": token},
                    )
                ok.append(str(member))
            except Exception as exc:
                logger.exception("BulkAssignRole error for %s", member.id)
                no_alloc.append(f"{member} (error: {exc})")

        lines_out = [f"✅ Assigned `{token}` to {len(ok)} members."]
        if not_found:
            lines_out.append(f"❌ Not found ({len(not_found)}): " + ", ".join(not_found[:10]))
        if no_alloc:
            lines_out.append(f"⚠️ No allocation ({len(no_alloc)}): " + ", ".join(no_alloc[:10]))
        await interaction.followup.send("\n".join(lines_out), ephemeral=True)


# ── Bulk Remove Role ──────────────────────────────────────────────────────────

class BulkRemoveRoleModal(discord.ui.Modal, title="Bulk Remove Role"):
    users_input = discord.ui.TextInput(
        label="Discord usernames or IDs (one per line)",
        style=discord.TextStyle.paragraph,
        placeholder="johndoe\n123456789012345678\nJane Doe",
        required=True,
        max_length=4000,
    )
    role_token = discord.ui.TextInput(
        label="Role token to remove",
        placeholder="BB_Access",
        required=True,
        max_length=100,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        token = self.role_token.value.strip()
        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        if not guild:
            await interaction.followup.send("Guild not found.", ephemeral=True)
            return

        lines = [l.strip() for l in self.users_input.value.splitlines() if l.strip()]
        ok: List[str] = []
        no_alloc: List[str] = []
        not_found: List[str] = []

        for line in lines:
            member = await _resolve_member_by_query(guild, line)
            if member is None:
                not_found.append(line)
                continue
            rec = await db.get_user(member.id)
            email = (rec.get("email") or "").strip() if rec else ""
            if not email:
                no_alloc.append(str(member))
                continue
            try:
                assert db.pool is not None
                async with db.pool.acquire() as conn:
                    alloc = await conn.fetchrow("SELECT projects FROM allocations WHERE email = $1", email)
                    if alloc is None:
                        no_alloc.append(str(member))
                        continue
                    new_tokens = [t for t in split_projects_str(alloc["projects"]) if t != token]
                    await conn.execute(
                        "UPDATE allocations SET projects=$1, updated_at=NOW() WHERE email=$2",
                        _projects_to_db(new_tokens),
                        email,
                    )
                allowed = allowed_managed_access_names_from_tokens(guild, new_tokens)
                await sync_managed_access_roles(member, allowed, "Admin panel: bulk remove role")
                if isinstance(interaction.user, discord.Member):
                    await db.log_admin_action(
                        interaction.user,
                        "bulk_role_removal",
                        target_discord_id=member.id,
                        target_email=email,
                        details={"role_token": token, "remaining": new_tokens},
                    )
                ok.append(str(member))
            except Exception as exc:
                logger.exception("BulkRemoveRole error for %s", member.id)
                no_alloc.append(f"{member} (error: {exc})")

        lines_out = [f"✅ Removed `{token}` from {len(ok)} members."]
        if not_found:
            lines_out.append(f"❌ Not found ({len(not_found)}): " + ", ".join(not_found[:10]))
        if no_alloc:
            lines_out.append(f"⚠️ No allocation ({len(no_alloc)}): " + ", ".join(no_alloc[:10]))
        await interaction.followup.send("\n".join(lines_out), ephemeral=True)


# ── Bulk Server Remove ────────────────────────────────────────────────────────

class BulkServerRemoveModal(discord.ui.Modal, title="Bulk Server Remove (Kick)"):
    users_input = discord.ui.TextInput(
        label="Discord usernames or IDs (one per line)",
        style=discord.TextStyle.paragraph,
        placeholder="johndoe\n123456789012345678\nJane Doe",
        required=True,
        max_length=4000,
    )
    reason = discord.ui.TextInput(
        label="Reason (optional)",
        required=False,
        max_length=500,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        if not guild:
            await interaction.followup.send("Guild not found.", ephemeral=True)
            return

        kick_reason = (self.reason.value or "").strip() or "Bulk removal by admin"
        lines = [l.strip() for l in self.users_input.value.splitlines() if l.strip()]
        kicked: List[str] = []
        skipped: List[str] = []
        not_found: List[str] = []
        me = guild.me

        for line in lines:
            member = await _resolve_member_by_query(guild, line)
            if member is None:
                not_found.append(line)
                continue
            if member.bot or member.id == guild.owner_id:
                skipped.append(f"{member} (bot/owner)")
                continue
            if me and member.top_role >= me.top_role:
                skipped.append(f"{member} (higher role)")
                continue
            rec = await db.get_user(member.id)
            alloc_email = (rec.get("email") or "").strip() if rec else ""
            try:
                await member.kick(reason=kick_reason[:500])
                if alloc_email:
                    await db.set_allocation_status_by_email(alloc_email, "REVOKE")
                if isinstance(interaction.user, discord.Member):
                    await db.log_admin_action(
                        interaction.user,
                        "bulk_server_removal",
                        target_discord_id=member.id,
                        target_email=alloc_email or None,
                        details={"reason": kick_reason},
                    )
                kicked.append(str(member))
            except discord.Forbidden:
                skipped.append(f"{member} (forbidden)")
            except discord.HTTPException as exc:
                skipped.append(f"{member} (error: {exc})")

        lines_out = [f"✅ Kicked {len(kicked)} members."]
        if not_found:
            lines_out.append(f"❌ Not found ({len(not_found)}): " + ", ".join(not_found[:10]))
        if skipped:
            lines_out.append(f"⚠️ Skipped ({len(skipped)}): " + ", ".join(skipped[:10]))
        await interaction.followup.send("\n".join(lines_out), ephemeral=True)


# ── Role Config ───────────────────────────────────────────────────────────────

class ManageManagedRolesModal(discord.ui.Modal, title="Manage Managed Access Roles"):
    action = discord.ui.TextInput(
        label="Action: add / remove / set",
        placeholder="add",
        required=True,
        max_length=10,
    )
    roles_input = discord.ui.TextInput(
        label="Role names (comma-separated)",
        placeholder="BB_Access,maitrix-coders",
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=2000,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        act = self.action.value.strip().lower()
        names = [r.strip() for r in re.split(r"[,;|]+", self.roles_input.value) if r.strip()]

        if act == "set":
            SETTINGS.managed_access_role_names.clear()
            SETTINGS.managed_access_role_names.update(names)
        elif act == "add":
            SETTINGS.managed_access_role_names.update(names)
        elif act == "remove":
            for n in names:
                SETTINGS.managed_access_role_names.discard(n)
        else:
            await interaction.followup.send("Action must be `add`, `remove`, or `set`.", ephemeral=True)
            return

        await db.save_role_config(managed=list(SETTINGS.managed_access_role_names))
        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "update_managed_roles_config",
                details={"action": act, "names": names, "current": sorted(SETTINGS.managed_access_role_names)},
            )
        current = ", ".join(sorted(SETTINGS.managed_access_role_names)) or "none"
        await interaction.followup.send(
            f"Managed roles updated (`{act}`).\n**Current:** `{current}`", ephemeral=True
        )


class ManageExemptRolesModal(discord.ui.Modal, title="Manage Exempt Roles"):
    action = discord.ui.TextInput(
        label="Action: add / remove / set",
        placeholder="add",
        required=True,
        max_length=10,
    )
    roles_input = discord.ui.TextInput(
        label="Role names (comma-separated)",
        placeholder="Admin,Support",
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=2000,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        act = self.action.value.strip().lower()
        names = [r.strip() for r in re.split(r"[,;|]+", self.roles_input.value) if r.strip()]

        if act == "set":
            SETTINGS.verification_exempt_role_names.clear()
            SETTINGS.verification_exempt_role_names.update(names)
        elif act == "add":
            SETTINGS.verification_exempt_role_names.update(names)
        elif act == "remove":
            for n in names:
                SETTINGS.verification_exempt_role_names.discard(n)
        else:
            await interaction.followup.send("Action must be `add`, `remove`, or `set`.", ephemeral=True)
            return

        await db.save_role_config(exempt=list(SETTINGS.verification_exempt_role_names))
        if isinstance(interaction.user, discord.Member):
            await db.log_admin_action(
                interaction.user,
                "update_exempt_roles_config",
                details={"action": act, "names": names, "current": sorted(SETTINGS.verification_exempt_role_names)},
            )
        current = ", ".join(sorted(SETTINGS.verification_exempt_role_names)) or "none"
        await interaction.followup.send(
            f"Exempt roles updated (`{act}`).\n**Current:** `{current}`", ephemeral=True
        )


class ViewRolesConfigView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=120)

    @discord.ui.button(label="Edit Managed Roles", style=discord.ButtonStyle.primary)
    async def edit_managed(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(ManageManagedRolesModal())

    @discord.ui.button(label="Edit Exempt Roles", style=discord.ButtonStyle.secondary)
    async def edit_exempt(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(ManageExemptRolesModal())


# ── User Status ───────────────────────────────────────────────────────────────

class UserStatusModal(discord.ui.Modal, title="User Status Lookup"):
    user_input = discord.ui.TextInput(
        label="Email address or Discord username / user ID",
        placeholder="user@example.com  or  johndoe  or  123456789012345678",
        required=True,
        max_length=200,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)

        guild = interaction.guild or bot.get_guild(SETTINGS.guild_id)
        if not guild:
            await interaction.followup.send("Guild not found.", ephemeral=True)
            return

        query = self.user_input.value.strip()
        member: Optional[discord.Member] = None
        discord_id: Optional[int] = None
        duv_rec: Optional[asyncpg.Record] = None
        alloc_rec: Optional[asyncpg.Record] = None

        if "@" in query:
            # ── Email path ──
            email_query = query.lower()
            alloc_rec = await db.fetch_allocation_by_email(email_query)
            assert db.pool is not None
            async with db.pool.acquire() as conn:
                duv_rec = await conn.fetchrow(
                    "SELECT * FROM discord_user_verification WHERE email = $1", email_query
                )
            if duv_rec:
                try:
                    discord_id = int(duv_rec["discord_user_id"])
                    member = guild.get_member(discord_id) or await guild.fetch_member(discord_id)
                except (TypeError, ValueError, discord.NotFound):
                    pass
        else:
            # ── Discord username / ID path ──
            member = await _resolve_member_by_query(guild, query)
            if member is None and query.isdigit():
                discord_id = int(query)
            elif member:
                discord_id = member.id

            if discord_id:
                duv_rec = await db.get_user(discord_id)

            if duv_rec:
                linked_email = (duv_rec.get("email") or "").strip()
                if linked_email:
                    alloc_rec = await db.fetch_allocation_by_email(linked_email)

        # ── Build embed ──
        if member:
            title = f"{member.display_name} ({member})"
            colour = discord.Colour.green() if duv_rec else discord.Colour.orange()
        else:
            title = f"User ID {discord_id}" if discord_id else f'"{query}"'
            colour = discord.Colour.red()

        embed = discord.Embed(title=title, colour=colour)

        # Discord presence (if member is in guild)
        if member:
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.add_field(name="Discord ID", value=str(member.id), inline=True)
            embed.add_field(name="Joined Server", value=f"<t:{int(member.joined_at.timestamp())}:R>" if member.joined_at else "Unknown", inline=True)
            managed_roles = [r.name for r in member.roles if r.name in SETTINGS.managed_access_role_names]
            embed.add_field(
                name="Current Managed Roles",
                value=", ".join(managed_roles) if managed_roles else "None",
                inline=False,
            )
        else:
            embed.add_field(name="Discord Status", value="⚠️ Not in server", inline=False)

        # DB record
        if duv_rec:
            status = duv_rec.get("status") or "UNKNOWN"
            verified = duv_rec.get("is_verified") or False
            v_status = duv_rec.get("verification_status") or "—"
            email = (duv_rec.get("email") or "").strip() or "—"
            last_seen = duv_rec.get("last_seen_at")
            access_revoked = duv_rec.get("access_revoked") or False
            assigned_roles_json = duv_rec.get("assigned_roles") or []
            assigned_roles_list = assigned_roles_json if isinstance(assigned_roles_json, list) else []

            status_icon = "✅" if verified else "❌"
            embed.add_field(
                name="Verification",
                value=(
                    f"{status_icon} **{status}** (`{v_status}`)\n"
                    f"Email: `{email}`\n"
                    f"Last seen: {f'<t:{int(last_seen.timestamp())}:R>' if last_seen else '—'}\n"
                    f"Access revoked: {'Yes ⚠️' if access_revoked else 'No'}"
                ),
                inline=False,
            )
            if assigned_roles_list:
                embed.add_field(
                    name="DB Assigned Roles",
                    value=", ".join(str(r) for r in assigned_roles_list) or "—",
                    inline=False,
                )
        else:
            embed.add_field(
                name="Database",
                value="❌ No record in `discord_user_verification`",
                inline=False,
            )

        # Allocation record
        if alloc_rec:
            alloc_active = alloc_rec.get("active")
            alloc_status = alloc_rec.get("status") or "—"
            alloc_projects = alloc_rec.get("projects") or "—"
            alloc_updated = alloc_rec.get("updated_at")
            active_icon = "✅" if alloc_active else "🔴"
            embed.add_field(
                name="Allocation",
                value=(
                    f"{active_icon} Active: `{alloc_active}` · Status: `{alloc_status}`\n"
                    f"Projects: `{alloc_projects}`\n"
                    f"Updated: {f'<t:{int(alloc_updated.timestamp())}:R>' if alloc_updated else '—'}"
                ),
                inline=False,
            )
        elif duv_rec and (duv_rec.get("email") or "").strip():
            embed.add_field(
                name="Allocation",
                value=f"⚠️ No allocation row for `{duv_rec.get('email')}`",
                inline=False,
            )
        else:
            embed.add_field(name="Allocation", value="— Not linked", inline=False)

        if not member and not duv_rec:
            embed.description = "No Discord member or database record found for that query."

        await interaction.followup.send(embed=embed, ephemeral=True)


# ── Main AdminPanelView ───────────────────────────────────────────────────────

class AdminPanelView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Add User to Role",
        style=discord.ButtonStyle.success,
        custom_id="admin_add_user",
        row=0,
    )
    async def add_user(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(AddUserModal())

    @discord.ui.button(
        label="Remove User from Role",
        style=discord.ButtonStyle.danger,
        custom_id="admin_remove_role",
        row=0,
    )
    async def remove_role(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(RemoveRoleEmailModal())

    @discord.ui.button(
        label="View Members by Role",
        style=discord.ButtonStyle.secondary,
        custom_id="admin_view_role",
        row=1,
    )
    async def view_role(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_message(
            "Select a role:", view=ViewByRoleView(), ephemeral=True
        )

    @discord.ui.button(
        label="Edit Allocation",
        style=discord.ButtonStyle.primary,
        custom_id="admin_edit_alloc",
        row=1,
    )
    async def edit_alloc(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(EditAllocationEmailModal())

    @discord.ui.button(
        label="Reset / Re-verify User",
        style=discord.ButtonStyle.danger,
        custom_id="admin_reset_user",
        row=2,
    )
    async def reset_user_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(ResetUserModal())

    @discord.ui.button(
        label="Bulk Add Users",
        style=discord.ButtonStyle.secondary,
        custom_id="admin_bulk_add",
        row=2,
    )
    async def bulk_add(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_message(
            "How would you like to add users?", view=BulkAddChoiceView(), ephemeral=True
        )

    @discord.ui.button(
        label="Bulk Assign Role",
        style=discord.ButtonStyle.success,
        custom_id="admin_bulk_assign_role",
        row=3,
    )
    async def bulk_assign_role(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(BulkAssignRoleModal())

    @discord.ui.button(
        label="Bulk Remove Role",
        style=discord.ButtonStyle.danger,
        custom_id="admin_bulk_remove_role",
        row=3,
    )
    async def bulk_remove_role(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(BulkRemoveRoleModal())

    @discord.ui.button(
        label="Bulk Server Remove",
        style=discord.ButtonStyle.danger,
        custom_id="admin_bulk_server_remove",
        row=3,
    )
    async def bulk_server_remove(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(BulkServerRemoveModal())

    @discord.ui.button(
        label="User Status",
        style=discord.ButtonStyle.primary,
        custom_id="admin_user_status",
        row=4,
    )
    async def user_status(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        await interaction.response.send_modal(UserStatusModal())

    @discord.ui.button(
        label="Role Config",
        style=discord.ButtonStyle.secondary,
        custom_id="admin_role_config",
        row=4,
    )
    async def role_config(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        if not _is_panel_authorized(interaction):
            await interaction.response.send_message("Access denied.", ephemeral=True)
            return
        managed = ", ".join(sorted(SETTINGS.managed_access_role_names)) or "none"
        exempt = ", ".join(sorted(SETTINGS.verification_exempt_role_names)) or "none"
        await interaction.response.send_message(
            f"**Managed Roles** (require verification):\n`{managed}`\n\n"
            f"**Exempt Roles** (skip verification):\n`{exempt}`",
            view=ViewRolesConfigView(),
            ephemeral=True,
        )


# ── AdminPanel Cog ────────────────────────────────────────────────────────────

class AdminPanel(commands.Cog):
    def __init__(self, bot_instance: commands.Bot) -> None:
        self._bot = bot_instance

    @commands.Cog.listener()
    async def on_ready(self) -> None:
        await self._setup_panel()

    async def _setup_panel(self) -> None:
        guild = self._bot.get_guild(SETTINGS.guild_id)
        if not guild:
            logger.warning("AdminPanel: guild %s not found", SETTINGS.guild_id)
            return
        channel = discord.utils.get(guild.text_channels, name=ADMIN_PANEL_CHANNEL_NAME)
        if not channel:
            logger.warning(
                "AdminPanel: channel #%s not found — create it and restrict access to %s/%s",
                ADMIN_PANEL_CHANNEL_NAME,
                SETTINGS.admin_role_name,
                SUPPORT_ROLE_NAME,
            )
            return
        embed = _panel_embed()
        saved_id = await _load_admin_panel_id()
        if saved_id:
            try:
                msg = await channel.fetch_message(saved_id)
                await msg.edit(embed=embed, view=AdminPanelView())
                logger.info(
                    "AdminPanel: restored panel (message %s) in #%s",
                    saved_id,
                    ADMIN_PANEL_CHANNEL_NAME,
                )
                return
            except (discord.NotFound, discord.HTTPException):
                logger.info("AdminPanel: saved message not found, re-creating panel")
        msg = await channel.send(embed=embed, view=AdminPanelView())
        await _save_admin_panel_id(msg.id)
        logger.info(
            "AdminPanel: created new panel (message %s) in #%s",
            msg.id,
            ADMIN_PANEL_CHANNEL_NAME,
        )


# ============================================================
# Main
# ============================================================
async def main() -> None:
    async with bot:
        await bot.add_cog(AdminPanel(bot))
        await start_health_server()
        await bot.start(SETTINGS.discord_token)


if __name__ == "__main__":
    asyncio.run(main())