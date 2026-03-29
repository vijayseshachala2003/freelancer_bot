import os
import re
import json
import asyncio
import logging
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
# - Verify-first: managed access roles (MANAGED_ACCESS_ROLE_NAMES) are removed until verification succeeds; after verify, roles match `allocations.projects` (extras removed on sync)
# - Unverified + Unverified role gate channels; DB `status` = VERIFIED | NOT_VERIFIED (no Discord Verified role)
# - New joins: strip managed access roles, gate, ping in #verify-yourself; existing members audited on startup the same way
# - If someone has a managed access role but DB says not verified → strip access, gate, notice (compliance audit)
# - Verified users: resync managed access roles from `allocations` (by canonical `email` PK), else from DB assigned_roles snapshot
# - Hard revoke (!revoke_access / access_revoked): gate + strip managed access roles
# - Admins: !kick / !ban — allocations.status REVOKE/BAN (by stored allocation email); !audit_bluebird — members with any managed access role
# - VERIFICATION_EXEMPT_ROLE_NAMES (code): staff skip verify; marked DB exempt; no allocation resync / strip; Verify UI tells them they are exempt
# - On ready: optional channel overwrites on #verify-yourself — deny @everyone view, allow Unverified + bot (VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED)
# - Timeout: strip managed access roles + gate; verification state in PostgreSQL / Supabase
# - #verify-yourself: bot ensures a **Verify now** panel message exists (posted once if missing)
#
# Discord Developer Portal (Bot → Privileged Gateway Intents):
#   - Server Members Intent — required (member list, roles, on_member_join).
#   - Message Content Intent — required for prefix commands (!helpme, !kick, !ban, etc.).
#
# Channel permissions (gate model): gated categories/channels must allow invite roles (e.g. BB_Access) and
# explicitly deny Unverified for View Channel (or equivalent), or users will not be blocked despite DB logic.
#
# "Only #verify-yourself until verified" (Discord-side, required):
# - On categories/channels for real content: @everyone View=Deny (or leave off), BB_Access View=Allow, Unverified View=Deny.
# - On #verify-yourself: Unverified View=Allow (and @everyone or Unverified can read).
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
# Managed access Discord roles: edit MANAGED_ACCESS_ROLE_NAMES in this file (tuple below — not .env).
# Verification-exempt staff roles: VERIFICATION_EXEMPT_ROLE_NAMES in this file.
# VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED=true (default): bot sets #verify-yourself visible only to Unverified + bot.
#
# Optional:
# LOG_LEVEL=INFO
# STATUS_CHANNEL_NAME=bot-status


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

# User-facing copy: what they must supply to pass verification / keep access.
VERIFY_REQUIREMENTS_SHORT = (
    "**You must provide:** your **Deccan-associated email address** exactly as on your **active** allocation "
    "(not revoked or banned)."
)

VERIFY_PANEL_BODY = (
    "**Verification required** to use access channels.\n\n"
    "**What you need to provide:**\n"
    "• **Deccan-associated mail address** — the email on your allocation (we match the email or Discord-linked email on that row)\n"
    "• The allocation must be **active** and allowed to verify (not revoked or banned)\n\n"
    "Click **Verify now** below and enter your Deccan-associated email."
)

# =============================================================================
# Project allocation (how it works)
# -----------------------------------------------------------------------------
# 1) Table `allocations` (Postgres): one row per person, keyed by `email`. Columns include `projects` (text),
#    `active`, `status` (ACTIVE / REVOKE / BAN), optional `discord_email`, etc.
#
# 2) The `projects` column holds one or more tokens separated by comma, semicolon, slash, or pipe, e.g.:
#      BB_Access, BB-Access, SomeOtherRole
#    Each token must be the EXACT Discord role name as it appears in Server Settings → Roles, and each
#    name must appear in MANAGED_ACCESS_ROLE_NAMES below. The bot does not build names from a suffix pattern.
#
#    Optional `discord_email` on `allocations`: set this to the member's Discord username (`member.name`) or
#    their global display name (`member.global_name`) — normalized, case/spacing-insensitive. When exactly one
#    allocation row matches on join (or compliance), the bot auto-completes verification and assigns roles from
#    that row's `projects` using the row's primary `email` as the canonical allocation key (no Discord user id
#    stored on `allocations`).
#
# 3) On successful verification, the bot matches the user's email to exactly one allocation row, reads
#    `projects`, and syncs Discord: add each listed managed role (if it exists on the server) and **remove**
#    any other MANAGED_ACCESS_ROLE_NAMES the member still has (e.g. from a manual invite or old allocation).
#    Those same role names are also removed on revoke, gate, failed verify, and audit.
#
# 4) Resync (verified users): same sync from the live `allocations` row by `email` (empty `projects` clears
#    all managed access roles). If the allocation row is missing or not verifiable, uses the `assigned_roles`
#    JSON snapshot on `discord_user_verification` as the allowed set.
#
# 5) `!audit_bluebird` runs the scoped compliance pass on every member who currently has at least one role
#    listed in MANAGED_ACCESS_ROLE_NAMES.
# =============================================================================

# Exact Discord role names the bot may assign (from allocations.projects) and strip on revoke/gate/audit.
# Case-sensitive — must match Server Settings → Roles. Add every project access role you use.
MANAGED_ACCESS_ROLE_NAMES: Tuple[str, ...] = (
    "BB_Access",
    "BB-Access",
    "AE-Access",
)

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
    managed_access_role_names: frozenset[str] = field(default_factory=frozenset)
    verification_exempt_role_names: frozenset[str] = field(default_factory=frozenset)
    restrict_verify_channel_to_unverified: bool = True


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

    managed = frozenset(MANAGED_ACCESS_ROLE_NAMES)
    if not managed:
        raise RuntimeError(
            "MANAGED_ACCESS_ROLE_NAMES in bot_verifier.py must contain at least one Discord role name."
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
        verification_exempt_role_names=frozenset(VERIFICATION_EXEMPT_ROLE_NAMES),
        restrict_verify_channel_to_unverified=os.getenv(
            "VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED", "true"
        ).lower()
        in ("1", "true", "yes"),
    )

    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return settings


SETTINGS = get_settings()

PORT = int(os.getenv("PORT", "8080"))


def norm_str(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value).strip().lower())


def split_projects_str(value: Any) -> List[str]:
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    parts = re.split(r"[,;/|]+", text)
    return [p.strip() for p in parts if p and p.strip()]


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


def get_projects_from_allocation(row: Dict[str, Any]) -> List[str]:
    if not allocation_row_can_verify(row):
        return []
    return split_projects_str(row.get("projects"))


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
        logger.info("Connected to database")

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

                CREATE TABLE IF NOT EXISTS allocations (
                    email TEXT PRIMARY KEY,
                    discord_email TEXT,
                    full_name TEXT,
                    projects TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_allocations_discord_email ON allocations (discord_email);

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
                    last_error = NULL;
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
                SELECT email, discord_email, full_name, projects, active, status
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
                SELECT email, discord_email, full_name, projects, active, status
                FROM allocations
                WHERE email = $1
                """,
                em,
            )
        return dict(row) if row else None

    async def find_allocation_match(self, email: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Match a single allocation row by normalized email or discord_email."""
        rows = await self.fetch_allocations()
        email_n = norm_str(email)
        matches: List[Dict[str, Any]] = []
        for row in rows:
            row_email = norm_str(row.get("email") or row.get("discord_email"))
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

    async def fetch_allocations_matching_discord_link_handle(self, handle: str) -> List[Dict[str, Any]]:
        """Allocations whose `discord_email` field matches this handle (norm_str equality)."""
        nh = norm_str(handle)
        if not nh:
            return []
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT email, discord_email, full_name, projects, active, status
                FROM allocations
                WHERE discord_email IS NOT NULL AND BTRIM(discord_email) != ''
                """
            )
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            if norm_str(d.get("discord_email")) == nh:
                out.append(d)
        return out


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
    Resolve an `allocations.projects` token to a guild role.
    Token must exactly match a name in MANAGED_ACCESS_ROLE_NAMES and exist on the server.
    """
    t = project_token.strip()
    if not t or t not in SETTINGS.managed_access_role_names:
        return None
    return get_role(guild, t)


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


def allowed_managed_access_names_for_projects(
    guild: discord.Guild, project_tokens: List[str]
) -> frozenset[str]:
    """Discord role names the allocation allows (tokens resolved on this guild)."""
    names: set[str] = set()
    for token in project_tokens:
        role = resolve_project_role(guild, token)
        if role:
            names.add(role.name)
        else:
            logger.warning(
                "Project token '%s' not in MANAGED_ACCESS_ROLE_NAMES or no Discord role with that exact name on server",
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
        projects = get_projects_from_allocation(alloc)
        allowed = allowed_managed_access_names_for_projects(member.guild, projects)
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


async def try_auto_verify_from_allocation_discord_link(member: discord.Member) -> bool:
    """
    If exactly one verifiable allocation row has `discord_email` matching this member's Discord username
    or global display name (normalized), complete verification and apply `projects` from that row.
    Canonical allocation key remains `allocations.email` (PK), not Discord user id.
    """
    if member.bot:
        return False
    if member_is_verification_exempt(member):
        return False

    candidates: Dict[str, Dict[str, Any]] = {}
    handles: List[str] = [member.name]
    gn = getattr(member, "global_name", None)
    if gn and str(gn).strip():
        handles.append(str(gn).strip())

    for h in handles:
        for row in await db.fetch_allocations_matching_discord_link_handle(h):
            em = str(row.get("email") or "").strip()
            if em:
                candidates[em] = row

    if len(candidates) != 1:
        if len(candidates) > 1:
            logger.warning(
                "Auto-verify skipped for member %s: multiple allocations match discord_email / display (%s rows)",
                member.id,
                len(candidates),
            )
        return False

    row = next(iter(candidates.values()))
    if not allocation_row_can_verify(row):
        logger.info(
            "Auto-verify skipped for member %s: allocation %s not verifiable",
            member.id,
            row.get("email"),
        )
        return False

    typed = str(row.get("email") or "").strip()
    try:
        await finalize_verified_member(member, row, typed_email=typed)
    except Exception:
        logger.exception("Auto-verify finalize failed for member %s", member.id)
        return False

    logger.info(
        "Auto-verified member %s from allocations.discord_email → allocation email=%s",
        member.id,
        typed,
    )
    return True


def member_access_role_names(member: discord.Member) -> List[str]:
    return [r.name for r in member.roles if is_access_role_name(r.name)]


async def gate_member(member: discord.Member, reason: str) -> None:
    """Add Unverified; remove legacy Verified role. Does not remove managed access roles (use revoke_member_access for verify-first)."""
    await assign_role_if_missing(member, SETTINGS.unverified_role_name, reason)
    await remove_role_if_present(member, SETTINGS.verified_role_name, reason)


async def revoke_member_access(member: discord.Member, reason: str) -> None:
    """Gate plus remove all managed access roles (hard revocation)."""
    await gate_member(member, reason)
    await remove_all_access_roles(member)


async def finalize_verified_member(
    member: discord.Member, source_row: Dict[str, Any], typed_email: str
) -> Tuple[List[str], List[str]]:
    """
    Identity verified: remove Unverified / legacy Verified; assign managed access roles from `allocations.projects`; DB status=VERIFIED.
    Stores canonical `allocations.email` (PK) on the verification row for resync and kick/ban.
    Returns (projects_logged, assigned_role_names).
    """
    canonical_email = str(source_row.get("email") or "").strip() or typed_email.strip()
    await remove_role_if_present(member, SETTINGS.unverified_role_name, "Verification success")
    await remove_role_if_present(member, SETTINGS.verified_role_name, "Verification success (legacy Verified role)")
    projects_logged = get_projects_from_allocation(source_row)
    allowed = allowed_managed_access_names_for_projects(member.guild, projects_logged)
    assigned_roles = await sync_managed_access_roles(
        member, allowed, "Verification success: allocation projects"
    )
    await db.mark_verified(
        discord_user_id=member.id,
        guild_id=member.guild.id,
        member_name=str(member),
        email=canonical_email,
        assigned_projects=projects_logged,
        assigned_roles=assigned_roles,
        source_row=source_row,
    )
    return projects_logged, assigned_roles


async def send_status_message(guild: discord.Guild, content: str) -> None:
    if not SETTINGS.status_channel_name:
        return
    channel = get_channel_by_name(guild, SETTINGS.status_channel_name)
    if channel and isinstance(channel, discord.TextChannel):
        try:
            await channel.send(content)
        except Exception as e:
            logger.warning("Could not send status message: %s", e)


async def send_verification_required_notice(member: discord.Member) -> None:
    """
    Tell new gated members they must verify. Posts in the server first (not bot DMs):
    1) #verify-yourself  2) server system channel  3) DM last resort.
    Ensure the verify channel (or system channel) allows the Unverified role to *View Channel*
    if members must read the notice there.
    """
    if member_is_verification_exempt(member):
        return
    guild = member.guild
    verify_ch = get_channel_by_name(guild, VERIFY_CHANNEL_NAME)
    if verify_ch and isinstance(verify_ch, discord.TextChannel):
        where = f" Use the **Verify now** button in this channel."
    else:
        where = (
            f" Open **#{VERIFY_CHANNEL_NAME}** (or wherever the verify panel is) and use **Verify now**."
        )

    body = (
        "You need to verify yourself first to get channel access.\n"
        + VERIFY_REQUIREMENTS_SHORT
        + "\n"
        + where
    )

    # 1) In-server: verify channel (public server message with ping + Verify now button)
    if verify_ch and isinstance(verify_ch, discord.TextChannel):
        try:
            await verify_ch.send(f"{member.mention} {body}", view=VerifyView())
            logger.info("Verification notice posted in #%s for member %s", VERIFY_CHANNEL_NAME, member.id)
            return
        except discord.HTTPException as exc:
            logger.warning("Verification notice: could not send to #%s: %s", VERIFY_CHANNEL_NAME, exc)

    # 2) Server system / welcome channel (Server Settings → Overview)
    if guild.system_channel and isinstance(guild.system_channel, discord.TextChannel):
        try:
            await guild.system_channel.send(f"{member.mention} {body}", view=VerifyView())
            logger.info("Verification notice posted in system channel for member %s", member.id)
            return
        except discord.HTTPException as exc:
            logger.warning("Verification notice: system channel send failed: %s", exc)

    # 3) Last resort: private DM from the bot
    try:
        await member.send(
            "You need to verify yourself first to get channel access.\n"
            + VERIFY_REQUIREMENTS_SHORT
            + f"\nUse **Verify now** in the **#{VERIFY_CHANNEL_NAME}** channel in the server."
        )
        logger.info("Verification notice sent via DM to %s (no in-server channel worked)", member.id)
    except discord.Forbidden:
        logger.warning(
            "Verification notice: no in-server delivery and cannot DM %s — check #%s / system channel / bot perms",
            member.id,
            VERIFY_CHANNEL_NAME,
        )
    except discord.HTTPException as exc:
        logger.warning("Verification notice: DM failed for %s: %s", member.id, exc)


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
class VerifyModal(discord.ui.Modal, title="Discord Access Verification"):
    email = discord.ui.TextInput(
        label="Deccan-associated mail address",
        placeholder="Your Deccan-associated email as on your allocation",
        required=True,
        max_length=120,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Guild context missing.", ephemeral=True)
            return

        # Defer immediately: DB + role work must not block the initial interaction (3s limit → 10062).
        try:
            await interaction.response.defer(ephemeral=True)
        except discord.NotFound:
            logger.warning(
                "Verify modal: interaction expired before defer (10062) — try again after heavy server load."
            )
            return

        if member_is_verification_exempt(interaction.user):
            await interaction.followup.send(
                "Your role does not require verification.",
                ephemeral=True,
            )
            return

        record = await db.get_user(interaction.user.id)
        if record and record.get("access_revoked"):
            await interaction.followup.send(
                "Your access is being revoked or was revoked. Wait a moment or contact an admin.",
                ephemeral=True,
            )
            return
        if record and member_db_verified(record):
            await interaction.followup.send(
                "You are already verified (status is VERIFIED). No action needed.",
                ephemeral=True,
            )
            return

        email = str(self.email.value).strip()

        matched, row, message = await db.find_allocation_match(email=email)
        if not matched or not row:
            await db.mark_failed_attempt(interaction.user.id, message)
            await gate_member(interaction.user, "Verification failed")
            await interaction.followup.send(
                f"Verification failed: {message}",
                ephemeral=True,
            )
            return

        try:
            projects_logged, assigned_roles = await finalize_verified_member(
                interaction.user,
                source_row=row,
                typed_email=email,
            )
        except Exception:
            logger.exception("finalize_verified_member failed for user %s", interaction.user.id)
            await interaction.followup.send(
                "Verification could not complete due to a server error. Please try again or contact an admin.",
                ephemeral=True,
            )
            return

        project_text = ", ".join(projects_logged) if projects_logged else "None (allocation row)"
        role_text = ", ".join(assigned_roles) if assigned_roles else "No matching managed access roles on server (check MANAGED_ACCESS_ROLE_NAMES and Discord role names)"
        await interaction.followup.send(
            f"Verification successful.\n"
            f"Discord user ID (stored): `{interaction.user.id}`\n"
            f"Allocation projects: {project_text}\n"
            f"Roles assigned: {role_text}",
            ephemeral=True,
        )
        canon = str(row.get("email") or "").strip()
        await send_status_message(
            interaction.guild,
            f"✅ Verified: {interaction.user.mention} | allocation_email={canon} | roles: {role_text}",
        )


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify now", style=discord.ButtonStyle.success, custom_id="verify_now_button")
    async def verify_now(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Guild context missing.", ephemeral=True)
            return

        if member_is_verification_exempt(interaction.user):
            await interaction.response.send_message(
                "Your role does not require verification.",
                ephemeral=True,
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
    """Post a single Verify panel in #verify-yourself if the bot has not already done so."""
    ch = get_channel_by_name(guild, VERIFY_CHANNEL_NAME)
    if not ch or not isinstance(ch, discord.TextChannel):
        logger.warning("Verify panel: channel #%s not found", VERIFY_CHANNEL_NAME)
        return
    try:
        async for msg in ch.history(limit=40):
            if msg.author == guild.me and msg.components:
                for row in msg.components:
                    for comp in row.children:
                        if getattr(comp, "custom_id", None) == "verify_now_button":
                            logger.info("Verify panel already in #%s (msg %s)", VERIFY_CHANNEL_NAME, msg.id)
                            return
    except discord.HTTPException as exc:
        logger.warning("Verify panel: cannot read #%s history: %s", VERIFY_CHANNEL_NAME, exc)
        return

    try:
        await ch.send(
            VERIFY_PANEL_BODY,
            view=VerifyView(),
        )
        logger.info("Posted Verify panel in #%s", VERIFY_CHANNEL_NAME)
    except discord.HTTPException as exc:
        logger.warning("Verify panel: could not post in #%s: %s", VERIFY_CHANNEL_NAME, exc)


async def ensure_verify_channel_permissions(guild: discord.Guild) -> None:
    """
    Restrict #verify-yourself so @everyone cannot view; allow Unverified + bot only.
    Staff without Unverified then cannot read verify pings/panel (configure VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED=false to skip).
    Requires bot: Manage Channels; bot role should be above @everyone for overwrites to apply reliably.
    """
    if not SETTINGS.restrict_verify_channel_to_unverified:
        return
    ch = get_channel_by_name(guild, VERIFY_CHANNEL_NAME)
    if not ch or not isinstance(ch, discord.TextChannel):
        logger.warning("Verify channel permissions: #%s not found", VERIFY_CHANNEL_NAME)
        return
    me = guild.me
    if not me:
        return
    unverified = get_role(guild, SETTINGS.unverified_role_name)
    if not unverified:
        logger.warning(
            "Verify channel permissions: role %r missing — create it or disable auto-restrict",
            SETTINGS.unverified_role_name,
        )
        return
    try:
        await ch.set_permissions(
            guild.default_role,
            view_channel=False,
            reason="Verify-yourself: only Unverified + bot should see this channel",
        )
        await ch.set_permissions(
            unverified,
            view_channel=True,
            read_message_history=True,
            reason="Members who must verify can read this channel",
        )
        await ch.set_permissions(
            me,
            view_channel=True,
            send_messages=True,
            embed_links=True,
            attach_files=True,
            read_message_history=True,
            manage_messages=True,
            reason="Bot verify panel and notices",
        )
        logger.info(
            "Set #%s: deny view @everyone; allow %s + bot",
            VERIFY_CHANNEL_NAME,
            SETTINGS.unverified_role_name,
        )
    except discord.Forbidden:
        logger.warning(
            "Could not set #%s permissions — bot needs Manage Channels (and sufficient role position)",
            VERIFY_CHANNEL_NAME,
        )
    except discord.HTTPException as exc:
        logger.warning("Verify channel permission update failed: %s", exc)


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
    await ensure_verify_channel_permissions(guild)
    await ensure_verify_panel_in_channel(guild)

    if not timeout_cleanup_loop.is_running():
        timeout_cleanup_loop.start()

    if not revoke_poll_loop.is_running():
        revoke_poll_loop.start()

    if not verification_compliance_loop.is_running():
        verification_compliance_loop.start()

    if SETTINGS.audit_on_startup:
        asyncio.create_task(run_full_verification_compliance_audit(guild, initial_delay=True))

    logger.info("Bot is ready")


@bot.event
async def setup_hook() -> None:
    await db.connect()
    logger.info("Allocation data is read from PostgreSQL table `allocations`.")
    # Persistent views: register once per process (on_ready can run again on reconnect).
    bot.add_view(VerifyView())


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

    if await try_auto_verify_from_allocation_discord_link(member):
        logger.info("Member %s auto-verified on join via allocations.discord_email → projects from DB", member.id)
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
    await send_verification_required_notice(member)


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
    Not verified (or no record) → strip managed access roles, gate; if they had access roles, ping verify-yourself.
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
                if await try_auto_verify_from_allocation_discord_link(member):
                    verified_cleared += 1
                    continue
                had = member_access_role_names(member)
                await revoke_member_access(member, "Compliance audit: not verified")
                if had:
                    await send_verification_required_notice(member)
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
    - else → strip managed access roles, gate, notify if they had access
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
    if await try_auto_verify_from_allocation_discord_link(member):
        return "verified"
    had = member_access_role_names(member)
    await revoke_member_access(member, reason)
    if had:
        await send_verification_required_notice(member)
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


@tasks.loop(minutes=30)
async def verification_compliance_loop() -> None:
    """Re-run full verify-first compliance pass every 30 minutes."""
    guild = bot.get_guild(SETTINGS.guild_id)
    if not guild:
        return
    await run_full_verification_compliance_audit(guild, announce=False, initial_delay=False)


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
        "**Verify first:** managed access roles (see `MANAGED_ACCESS_ROLE_NAMES` in bot_verifier.py) are removed until you complete verification. After verify, roles are assigned from `allocations.projects`.\n"
        + VERIFY_REQUIREMENTS_SHORT
        + "\n"
        "Use **Verify now** below (or in **#verify-yourself**).\n"
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
    await send_verification_required_notice(target)
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
        await send_verification_required_notice(member)
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

    logger.info("Ban: %s by %s (%s)", uid, ctx.author.id, ban_reason)
    await ctx.reply(f"Banned **{member}** ({ban_reason}).{alloc_note}")


# ============================================================
# Main
# ============================================================
async def main() -> None:
    async with bot:
        await start_health_server()
        await bot.start(SETTINGS.discord_token)


if __name__ == "__main__":
    asyncio.run(main())