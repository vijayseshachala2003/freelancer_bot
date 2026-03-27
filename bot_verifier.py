import os
import re
import json
import asyncio
import logging
from dataclasses import dataclass
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
# - New members are blocked behind a verification channel
# - Users verify with email + soul_id using a modal
# - Verification happens only once per user unless reset manually
# - Existing members can be audited and mismatches removed
# - Unverified users older than 24 hours are removed from gated roles
# - Project access comes from PostgreSQL table `allocations` (email + soul_id match)
# - Verification state is stored in PostgreSQL / Supabase
# - Set access_revoked=true in DB (or use !revoke_access) to remove Discord access
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
# VERIFY_CHANNEL_NAME=verify-yourself
# UNVERIFIED_ROLE_NAME=Unverified
# VERIFIED_ROLE_NAME=Verified
# ADMIN_ROLE_NAME=Admin
# VERIFICATION_TIMEOUT_HOURS=24
# AUDIT_ON_STARTUP=true
# ACCESS_ROLE_SUFFIX=_Access
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


# ============================================================
# Config
# ============================================================
@dataclass
class Settings:
    discord_token: str
    guild_id: int
    database_url: str
    verify_channel_name: str = "verify-yourself"
    unverified_role_name: str = "Unverified"
    verified_role_name: str = "Verified"
    admin_role_name: str = "Admin"
    verification_timeout_hours: int = 24
    audit_on_startup: bool = True
    access_role_suffix: str = "_Access"
    status_channel_name: Optional[str] = None


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

    settings = Settings(
        discord_token=require("DISCORD_TOKEN"),
        guild_id=int(require("GUILD_ID") or 0),
        database_url=database_url if database_url else "",
        verify_channel_name=os.getenv("VERIFY_CHANNEL_NAME", "verify-yourself"),
        unverified_role_name=os.getenv("UNVERIFIED_ROLE_NAME", "Unverified"),
        verified_role_name=os.getenv("VERIFIED_ROLE_NAME", "Verified"),
        admin_role_name=os.getenv("ADMIN_ROLE_NAME", "Admin"),
        verification_timeout_hours=int(os.getenv("VERIFICATION_TIMEOUT_HOURS", "24")),
        audit_on_startup=os.getenv("AUDIT_ON_STARTUP", "true").lower() == "true",
        access_role_suffix=os.getenv("ACCESS_ROLE_SUFFIX", "_Access"),
        status_channel_name=os.getenv("STATUS_CHANNEL_NAME"),
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


def get_projects_from_allocation(row: Dict[str, Any]) -> List[str]:
    if not allocation_row_is_active(row):
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
        self.pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)
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
                    soul_id TEXT,
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

                CREATE INDEX IF NOT EXISTS idx_duv_soul_id
                ON discord_user_verification (soul_id);

                CREATE INDEX IF NOT EXISTS idx_duv_email
                ON discord_user_verification (email);

                ALTER TABLE discord_user_verification
                ADD COLUMN IF NOT EXISTS access_revoked BOOLEAN NOT NULL DEFAULT FALSE;

                CREATE INDEX IF NOT EXISTS idx_duv_access_revoked
                ON discord_user_verification (guild_id, access_revoked)
                WHERE access_revoked = TRUE;

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
        soul_id: str,
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
                    soul_id,
                    is_verified,
                    verification_status,
                    verified_at,
                    last_seen_at,
                    assigned_projects,
                    assigned_roles,
                    source_row,
                    verification_locked,
                    removed_for_timeout,
                    access_revoked
                ) VALUES (
                    $1, $2, $3, $4, $5, TRUE, 'verified', NOW(), NOW(), $6::jsonb, $7::jsonb, $8::jsonb, TRUE, FALSE, FALSE
                )
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    guild_id = EXCLUDED.guild_id,
                    discord_username = EXCLUDED.discord_username,
                    email = EXCLUDED.email,
                    soul_id = EXCLUDED.soul_id,
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
                    last_error = NULL;
                """,
                str(discord_user_id),
                str(guild_id),
                member_name,
                email,
                soul_id,
                json.dumps(assigned_projects),
                json.dumps(assigned_roles),
                json.dumps(source_row, default=str),
            )

    async def mark_timeout_removed(self, discord_user_id: int, reason: str) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO discord_user_verification (
                    discord_user_id, guild_id, verification_status, removed_for_timeout, last_error
                ) VALUES ($1, $2, 'timed_out', TRUE, $3)
                ON CONFLICT (discord_user_id)
                DO UPDATE SET
                    verification_status = 'timed_out',
                    removed_for_timeout = TRUE,
                    last_error = EXCLUDED.last_error,
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
                  AND is_verified = FALSE
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
                    last_seen_at = NOW()
                WHERE discord_user_id = $1;
                """,
                str(discord_user_id),
            )

    async def fetch_allocations(self) -> List[Dict[str, Any]]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT soul_id, email, discord_email, full_name, projects, active
                FROM allocations
                """
            )
        return [dict(r) for r in rows]

    async def find_allocation_match(
        self, email: str, soul_id: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        rows = await self.fetch_allocations()
        email_n = norm_str(email)
        soul_n = norm_str(soul_id)

        for row in rows:
            row_email = norm_str(row.get("email") or row.get("discord_email"))
            row_soul = norm_str(row.get("soul_id"))
            if row_soul == soul_n and row_email == email_n:
                return True, row, "matched"

        for row in rows:
            row_soul = norm_str(row.get("soul_id"))
            if row_soul == soul_n:
                row_email = norm_str(row.get("email") or row.get("discord_email"))
                return False, row, f"Soul ID matched but email mismatched. Expected {row_email or 'unknown'}"

        for row in rows:
            row_email = norm_str(row.get("email") or row.get("discord_email"))
            if row_email == email_n:
                row_soul = norm_str(row.get("soul_id"))
                return False, row, f"Email matched but soul_id mismatched. Expected {row_soul or 'unknown'}"

        return False, None, "No matching user found in allocations"


# ============================================================
# Discord bot
# ============================================================
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
db = Database(SETTINGS.database_url)


# ============================================================
# Helpers
# ============================================================
def get_role(guild: discord.Guild, role_name: str) -> Optional[discord.Role]:
    return discord.utils.get(guild.roles, name=role_name)


def get_channel_by_name(guild: discord.Guild, channel_name: str) -> Optional[discord.abc.GuildChannel]:
    return discord.utils.get(guild.channels, name=channel_name)


def normalize_project_role_name(project_name: str) -> str:
    base = re.sub(r"\s+", "_", project_name.strip())
    return f"{base}{SETTINGS.access_role_suffix}"


async def ensure_roles_exist(guild: discord.Guild) -> None:
    for role_name in [SETTINGS.unverified_role_name, SETTINGS.verified_role_name]:
        if not get_role(guild, role_name):
            await guild.create_role(name=role_name, reason="Required verification role")
            logger.info("Created missing role: %s", role_name)


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
        if role.name.endswith(SETTINGS.access_role_suffix):
            await member.remove_roles(role, reason="Removing project access roles")
            removed.append(role.name)
    return removed


async def assign_project_roles(member: discord.Member, projects: List[str]) -> List[str]:
    assigned = []
    for project in projects:
        role_name = normalize_project_role_name(project)
        role = get_role(member.guild, role_name)
        if role:
            if role not in member.roles:
                await member.add_roles(role, reason="Verification success: assigning project role")
            assigned.append(role.name)
        else:
            logger.warning("Project role not found for project '%s' -> expected role '%s'", project, role_name)
    return assigned


async def lock_member_into_gate(member: discord.Member, reason: str) -> None:
    await assign_role_if_missing(member, SETTINGS.unverified_role_name, reason)
    await remove_role_if_present(member, SETTINGS.verified_role_name, reason)
    await remove_all_access_roles(member)


async def finalize_verified_member(member: discord.Member, projects: List[str], source_row: Dict[str, Any], email: str, soul_id: str) -> List[str]:
    await remove_role_if_present(member, SETTINGS.unverified_role_name, "Verification success")
    await assign_role_if_missing(member, SETTINGS.verified_role_name, "Verification success")
    assigned_roles = await assign_project_roles(member, projects)
    await db.mark_verified(
        discord_user_id=member.id,
        guild_id=member.guild.id,
        member_name=str(member),
        email=email,
        soul_id=soul_id,
        assigned_projects=projects,
        assigned_roles=assigned_roles,
        source_row=source_row,
    )
    return assigned_roles


async def send_status_message(guild: discord.Guild, content: str) -> None:
    if not SETTINGS.status_channel_name:
        return
    channel = get_channel_by_name(guild, SETTINGS.status_channel_name)
    if channel and isinstance(channel, discord.TextChannel):
        try:
            await channel.send(content)
        except Exception as e:
            logger.warning("Could not send status message: %s", e)


async def apply_access_revoke_in_discord(
    guild: discord.Guild, discord_user_id: int, reason: str
) -> bool:
    """
    Remove Verified + project roles (gate). Updates DB via apply_revoke_completed.
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
        await lock_member_into_gate(member, reason)
    except Exception as exc:
        logger.exception("Revoke: lock_member_into_gate failed for %s: %s", uid, exc)
        return False

    await db.apply_revoke_completed(uid)
    return True


# ============================================================
# Verification UI
# ============================================================
class VerifyModal(discord.ui.Modal, title="Discord Access Verification"):
    email = discord.ui.TextInput(
        label="Your email",
        placeholder="name@example.com",
        required=True,
        max_length=120,
    )
    soul_id = discord.ui.TextInput(
        label="Your Soul ID",
        placeholder="Enter your Soul ID",
        required=True,
        max_length=120,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Guild context missing.", ephemeral=True)
            return

        record = await db.get_user(interaction.user.id)
        if record and record.get("access_revoked"):
            await interaction.response.send_message(
                "Your access is being revoked or was revoked. Wait a moment or contact an admin.",
                ephemeral=True,
            )
            return
        if record and record["is_verified"] and record["verification_locked"]:
            await interaction.response.send_message(
                "You are already verified. No action needed.",
                ephemeral=True,
            )
            return

        email = str(self.email.value).strip()
        soul_id = str(self.soul_id.value).strip()

        matched, row, message = await db.find_allocation_match(email=email, soul_id=soul_id)
        if not matched or not row:
            await db.mark_failed_attempt(interaction.user.id, message)
            await lock_member_into_gate(interaction.user, "Verification failed")
            await interaction.response.send_message(
                f"Verification failed: {message}",
                ephemeral=True,
            )
            return

        if matched and not allocation_row_is_active(row):
            await db.mark_failed_attempt(
                interaction.user.id,
                "Allocation row is inactive (active=false)",
            )
            await lock_member_into_gate(interaction.user, "Verification failed: inactive allocation")
            await interaction.response.send_message(
                "Verification failed: this allocation is inactive. Contact an admin.",
                ephemeral=True,
            )
            return

        projects = get_projects_from_allocation(row)
        assigned_roles = await finalize_verified_member(
            interaction.user,
            projects=projects,
            source_row=row,
            email=email,
            soul_id=soul_id,
        )

        project_text = ", ".join(projects) if projects else "No projects mapped"
        role_text = ", ".join(assigned_roles) if assigned_roles else "No access roles assigned"
        await interaction.response.send_message(
            f"Verification successful.\n"
            f"Discord user ID (stored): `{interaction.user.id}`\n"
            f"Projects: {project_text}\n"
            f"Roles assigned: {role_text}",
            ephemeral=True,
        )
        await send_status_message(
            interaction.guild,
            f"✅ Verified: {interaction.user.mention} | soul_id={soul_id} | roles={role_text}",
        )


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify now", style=discord.ButtonStyle.success, custom_id="verify_now_button")
    async def verify_now(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Guild context missing.", ephemeral=True)
            return

        record = await db.get_user(interaction.user.id)
        if record and record.get("access_revoked"):
            await interaction.response.send_message(
                "Your access is being revoked or was revoked. Contact an admin if this is wrong.",
                ephemeral=True,
            )
            return
        if record and record["is_verified"] and record["verification_locked"]:
            await interaction.response.send_message("You are already verified.", ephemeral=True)
            return

        await interaction.response.send_modal(VerifyModal())


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
    bot.add_view(VerifyView())

    if not timeout_cleanup_loop.is_running():
        timeout_cleanup_loop.start()

    if not revoke_poll_loop.is_running():
        revoke_poll_loop.start()

    if SETTINGS.audit_on_startup:
        asyncio.create_task(run_full_audit(guild))

    logger.info("Bot is ready")


@bot.event
async def setup_hook() -> None:
    await db.connect()
    logger.info("Allocation data is read from PostgreSQL table `allocations`.")


@bot.event
async def on_member_join(member: discord.Member) -> None:
    if member.guild.id != SETTINGS.guild_id:
        return

    await db.touch_user(member.guild.id, member)

    record = await db.get_user(member.id)
    if record and record.get("access_revoked"):
        await lock_member_into_gate(member, "Access revoked (pending or active)")
        logger.info("Member %s has access_revoked flag; kept in gate", member)
        return

    if record and record["is_verified"] and record["verification_locked"]:
        logger.info("Member %s already verified historically; skipping gate", member)
        await assign_role_if_missing(member, SETTINGS.verified_role_name, "Previously verified user rejoined")
        assigned_roles = record["assigned_roles"] or []
        if isinstance(assigned_roles, str):
            assigned_roles = json.loads(assigned_roles)
        for role_name in assigned_roles:
            await assign_role_if_missing(member, role_name, "Previously verified access restore")
        return

    await lock_member_into_gate(member, "New member pending verification")
    logger.info("Member joined and placed in gate: %s", member)


# ============================================================
# Background jobs & audit
# ============================================================
async def run_full_audit(guild: discord.Guild) -> None:
    """Ensure verified members have correct roles; lock unverified members who have access roles."""
    await asyncio.sleep(2)
    logger.info("Starting full audit for guild %s", guild.id)
    try:
        for member in guild.members:
            if member.bot:
                continue
            record = await db.get_user(member.id)
            if record and record.get("access_revoked"):
                await lock_member_into_gate(member, "Audit: access_revoked flag set in DB")
                continue
            if record and record.get("is_verified") and record.get("verification_locked"):
                await assign_role_if_missing(member, SETTINGS.verified_role_name, "Audit: restore verified")
                await remove_role_if_present(member, SETTINGS.unverified_role_name, "Audit: verified user")
                assigned_roles = record["assigned_roles"] or []
                if isinstance(assigned_roles, str):
                    assigned_roles = json.loads(assigned_roles)
                for role_name in assigned_roles:
                    await assign_role_if_missing(member, role_name, "Audit: restore project access")
            else:
                has_access = any(
                    r.name.endswith(SETTINGS.access_role_suffix) for r in member.roles
                )
                if has_access:
                    await lock_member_into_gate(member, "Audit: unverified member had access roles")
        await send_status_message(guild, "✅ Audit completed.")
    except Exception as exc:
        logger.exception("Full audit failed: %s", exc)
        await send_status_message(guild, f"⚠️ Audit failed: {exc}")


@tasks.loop(minutes=30)
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

        try:
            await lock_member_into_gate(
                member,
                f"Verification timeout ({SETTINGS.verification_timeout_hours}h)",
            )
            await db.mark_timeout_removed(
                uid,
                f"Removed access after {SETTINGS.verification_timeout_hours}h without verification",
            )
            await send_status_message(
                guild,
                f"⏱️ Timeout: {member.mention} — verification window expired; access roles removed.",
            )
        except Exception as exc:
            logger.exception("Timeout cleanup failed for %s: %s", uid, exc)


@timeout_cleanup_loop.before_loop
async def before_timeout_cleanup_loop() -> None:
    await bot.wait_until_ready()


@tasks.loop(minutes=5)
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
    await ctx.reply(
        "Use the **Verify now** button in the verification channel and enter your email + Soul ID.\n"
        "Your Discord ID is stored automatically (you do not need to type it).\n"
        "`!reset_verification` — reset your verification (you can re-verify). "
        "Admins: `!reset_verification @user`.\n"
        "`!revoke_access @user` — admin only: remove their roles immediately (DB + Discord).\n"
        "Or set `access_revoked = true` in Supabase (`discord_user_verification`); the bot applies within ~5 minutes.\n"
        "Eligibility comes from the `allocations` table (email + soul_id + projects + active)."
    )


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
    await lock_member_into_gate(target, "Verification reset")
    await ctx.reply(f"Verification reset for {target.mention}. Use **Verify now** to complete again.")


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
        await ctx.reply(f"Access revoked for {member.mention}. They can use **Verify** again after re-approval.")
    else:
        await ctx.reply(
            f"Could not revoke in Discord for {member.mention}; DB flag may still be set — check logs."
        )


# ============================================================
# Main
# ============================================================
async def main() -> None:
    async with bot:
        await start_health_server()
        await bot.start(SETTINGS.discord_token)


if __name__ == "__main__":
    asyncio.run(main())