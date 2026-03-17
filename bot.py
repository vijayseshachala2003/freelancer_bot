import os
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple

import discord
from discord.ext import commands, tasks
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
from aiohttp import web

load_dotenv()

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("discord-allocation-bot")

# ----------------------------
# Env config
# ----------------------------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
GUILD_ID = int(os.getenv("GUILD_ID", "0"))
GOOGLE_SHEET_ID = os.getenv("GOOGLE_SHEET_ID", "").strip()
GOOGLE_WORKSHEET_NAME = os.getenv("GOOGLE_WORKSHEET_NAME", "allocations").strip()
SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "120"))
FREELANCER_ROLE_NAME = os.getenv("FREELANCER_ROLE_NAME", "Freelancer").strip()
ADMIN_ROLE_NAME = os.getenv("ADMIN_ROLE_NAME", "Admin").strip()
PORT = int(os.getenv("PORT", "8080"))

if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing.")
if not GUILD_ID:
    raise RuntimeError("GUILD_ID is missing or invalid.")
if not GOOGLE_SHEET_ID:
    raise RuntimeError("GOOGLE_SHEET_ID is missing.")

# ----------------------------
# Project -> Discord role map
# Extend this later as needed
# ----------------------------
PROJECT_ROLE_MAP: Dict[str, str] = {
    "AE": "AE_Access",
    "BB": "BB_Access",
}

MANAGED_PROJECT_ROLE_NAMES: Set[str] = set(PROJECT_ROLE_MAP.values())

# ----------------------------
# Google Sheets auth
# ----------------------------
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

# ----------------------------
# Discord intents
# ----------------------------
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# ----------------------------
# Health / status state
# ----------------------------
health_state = {
    "bot_ready": False,
    "last_sync_ok": False,
    "last_sync_message": "No sync has run yet.",
    "last_sync_updated_count": 0,
    "last_sync_skipped_count": 0,
    "last_sync_untouched_count": 0,
}

# ----------------------------
# In-memory cache
# ----------------------------
sheet_cache: Dict[str, Dict[str, str]] = {}
sheet_cache_by_discord_id: Dict[str, Dict[str, str]] = {}
sheet_headers: Dict[str, int] = {}
cache_last_loaded: Optional[float] = None

# ----------------------------
# Helpers
# ----------------------------
def normalize_projects(projects_raw: str) -> Set[str]:
    if not projects_raw:
        return set()
    return {
        part.strip().upper()
        for part in projects_raw.split(",")
        if part and part.strip()
    }

def normalize_bool(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}

def get_gspread_client():
    creds = Credentials.from_service_account_file("service_account.json", scopes=SCOPES)
    return gspread.authorize(creds)

def get_worksheet():
    client = get_gspread_client()
    sheet = client.open_by_key(GOOGLE_SHEET_ID)
    return sheet.worksheet(GOOGLE_WORKSHEET_NAME)

def read_all_rows() -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    ws = get_worksheet()
    rows = ws.get_all_records()

    headers = ws.row_values(1)
    header_map = {name.strip(): idx + 1 for idx, name in enumerate(headers)}

    cleaned_rows: List[Dict[str, str]] = []
    for row in rows:
        cleaned_rows.append({
            "soul_id": str(row.get("soul_id", "")).strip(),
            "full_name": str(row.get("full_name", "")).strip(),
            "email": str(row.get("email", "")).strip(),
            "discord_user_id": str(row.get("discord_user_id", "")).strip(),
            "discord_username": str(row.get("discord_username", "")).strip(),
            "projects": str(row.get("projects", "")).strip(),
            "active": str(row.get("active", "")).strip(),
        })

    return cleaned_rows, header_map

def rebuild_cache(rows: List[Dict[str, str]], headers: Dict[str, int]) -> None:
    global sheet_cache, sheet_cache_by_discord_id, sheet_headers, cache_last_loaded

    by_soul_id: Dict[str, Dict[str, str]] = {}
    by_discord_id: Dict[str, Dict[str, str]] = {}

    for row in rows:
        soul_id = row["soul_id"].strip().upper()
        discord_user_id = row["discord_user_id"].strip()

        if soul_id:
            by_soul_id[soul_id] = row
        if discord_user_id:
            by_discord_id[discord_user_id] = row

    sheet_cache = by_soul_id
    sheet_cache_by_discord_id = by_discord_id
    sheet_headers = headers
    cache_last_loaded = asyncio.get_event_loop().time()

def load_sheet_cache() -> None:
    rows, headers = read_all_rows()
    rebuild_cache(rows, headers)

def find_row_number_by_soul_id(ws, soul_id: str) -> Optional[int]:
    soul_id = soul_id.strip().upper()
    values = ws.col_values(1)  # assuming soul_id is first column
    for idx, value in enumerate(values[1:], start=2):
        if str(value).strip().upper() == soul_id:
            return idx
    return None

def link_discord_to_soul_id(soul_id: str, discord_user_id: int, discord_username: str) -> bool:
    ws = get_worksheet()
    row_number = find_row_number_by_soul_id(ws, soul_id)
    if not row_number:
        return False

    headers = ws.row_values(1)
    header_map = {name.strip(): idx + 1 for idx, name in enumerate(headers)}

    if "discord_user_id" not in header_map or "discord_username" not in header_map:
        raise RuntimeError("Sheet must contain 'discord_user_id' and 'discord_username' columns.")

    ws.update_cell(row_number, header_map["discord_user_id"], str(discord_user_id))
    ws.update_cell(row_number, header_map["discord_username"], discord_username)
    return True

def get_cached_row_by_soul_id(soul_id: str) -> Optional[Dict[str, str]]:
    return sheet_cache.get(soul_id.strip().upper())

def get_cached_row_by_discord_user_id(discord_user_id: int) -> Optional[Dict[str, str]]:
    return sheet_cache_by_discord_id.get(str(discord_user_id))

def is_admin_member(member: discord.Member) -> bool:
    return any(role.name == ADMIN_ROLE_NAME for role in member.roles)

async def ensure_base_freelancer_role(member: discord.Member) -> None:
    guild = member.guild
    freelancer_role = discord.utils.get(guild.roles, name=FREELANCER_ROLE_NAME)
    if freelancer_role and freelancer_role not in member.roles:
        await member.add_roles(freelancer_role, reason="Auto-assign base freelancer role")

async def sync_member_roles(member: discord.Member, row: Dict[str, str]) -> List[str]:
    changes: List[str] = []
    guild = member.guild

    await ensure_base_freelancer_role(member)

    active = normalize_bool(row["active"])
    desired_project_codes = normalize_projects(row["projects"]) if active else set()
    desired_role_names = {
        PROJECT_ROLE_MAP[code]
        for code in desired_project_codes
        if code in PROJECT_ROLE_MAP
    }

    current_managed_role_names = {
        role.name
        for role in member.roles
        if role.name in MANAGED_PROJECT_ROLE_NAMES
    }

    to_add = desired_role_names - current_managed_role_names
    to_remove = current_managed_role_names - desired_role_names

    for role_name in sorted(to_add):
        role = discord.utils.get(guild.roles, name=role_name)
        if role:
            await member.add_roles(role, reason=f"Project sync add for soul_id={row['soul_id']}")
            changes.append(f"added:{role_name}")
        else:
            logger.warning("Role '%s' does not exist in Discord.", role_name)

    for role_name in sorted(to_remove):
        role = discord.utils.get(guild.roles, name=role_name)
        if role:
            await member.remove_roles(role, reason=f"Project sync remove for soul_id={row['soul_id']}")
            changes.append(f"removed:{role_name}")

    return changes

async def run_full_sync() -> str:
    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        raise RuntimeError("Guild not found. Check GUILD_ID.")

    load_sheet_cache()

    updated_count = 0
    untouched_count = 0
    skipped_count = 0

    for member in guild.members:
        if member.bot:
            continue

        row = get_cached_row_by_discord_user_id(member.id)
        if row is None:
            skipped_count += 1
            continue

        changes = await sync_member_roles(member, row)
        if changes:
            updated_count += 1
            logger.info(
                "Updated member=%s soul_id=%s changes=%s",
                member.display_name,
                row["soul_id"],
                ", ".join(changes)
            )
        else:
            untouched_count += 1

    result = (
        f"sync complete | updated={updated_count} "
        f"untouched={untouched_count} skipped={skipped_count}"
    )

    health_state["last_sync_ok"] = True
    health_state["last_sync_message"] = result
    health_state["last_sync_updated_count"] = updated_count
    health_state["last_sync_skipped_count"] = skipped_count
    health_state["last_sync_untouched_count"] = untouched_count

    return result

# ----------------------------
# Discord events
# ----------------------------
@bot.event
async def on_ready():
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id)
    health_state["bot_ready"] = True

    try:
        load_sheet_cache()
        logger.info("Initial Google Sheet cache loaded successfully.")
    except Exception as exc:
        logger.exception("Initial sheet cache load failed: %s", exc)

    if not periodic_sync.is_running():
        periodic_sync.start()

@bot.event
async def on_member_join(member: discord.Member):
    if member.bot:
        return

    await ensure_base_freelancer_role(member)

    message = (
        "Welcome to the server.\n\n"
        "To activate your project access, please link your Soul ID by sending:\n"
        "`!link YOUR_SOUL_ID`\n\n"
        "Example:\n"
        "`!link SOUL1001`\n\n"
        "After linking, your project access will be assigned automatically."
    )

    try:
        await member.send(message)
        logger.info("Sent Soul ID prompt DM to user_id=%s", member.id)
    except discord.Forbidden:
        logger.warning("Could not DM user_id=%s. DMs may be disabled.", member.id)

# ----------------------------
# Commands
# ----------------------------
@bot.command(name="link")
async def link_command(ctx: commands.Context, soul_id: str):
    if not isinstance(ctx.author, discord.Member):
        await ctx.reply("This command must be used inside the server.")
        return

    soul_id = soul_id.strip().upper()

    try:
        success = link_discord_to_soul_id(
            soul_id=soul_id,
            discord_user_id=ctx.author.id,
            discord_username=str(ctx.author)
        )
    except Exception as exc:
        logger.exception("Link failed for soul_id=%s: %s", soul_id, exc)
        await ctx.reply(f"Link failed due to an internal error: {exc}")
        return

    if not success:
        await ctx.reply(f"Soul ID `{soul_id}` was not found in the Google Sheet.")
        return

    try:
        load_sheet_cache()
        row = get_cached_row_by_discord_user_id(ctx.author.id)
        if row is None:
            await ctx.reply(f"Soul ID `{soul_id}` linked, but no matching row was found after refresh.")
            return

        changes = await sync_member_roles(ctx.author, row)
        if changes:
            await ctx.reply(
                f"Linked successfully to `{soul_id}`.\n"
                f"Access update: {', '.join(changes)}"
            )
        else:
            await ctx.reply(f"Linked successfully to `{soul_id}`. No role changes were needed.")
    except Exception as exc:
        logger.exception("Post-link sync failed for soul_id=%s: %s", soul_id, exc)
        await ctx.reply(f"Linked to `{soul_id}`, but role sync failed: {exc}")

@bot.command(name="sync_now")
async def sync_now_command(ctx: commands.Context):
    if not isinstance(ctx.author, discord.Member) or not is_admin_member(ctx.author):
        await ctx.reply("You do not have permission to run this command.")
        return

    try:
        result = await run_full_sync()
        await ctx.reply(result)
    except Exception as exc:
        health_state["last_sync_ok"] = False
        health_state["last_sync_message"] = str(exc)
        logger.exception("Manual sync failed: %s", exc)
        await ctx.reply(f"Sync failed: {exc}")

@bot.command(name="sync_status")
async def sync_status_command(ctx: commands.Context):
    if not isinstance(ctx.author, discord.Member) or not is_admin_member(ctx.author):
        await ctx.reply("You do not have permission to run this command.")
        return

    await ctx.reply(
        f"bot_ready={health_state['bot_ready']}\n"
        f"last_sync_ok={health_state['last_sync_ok']}\n"
        f"message={health_state['last_sync_message']}\n"
        f"updated={health_state['last_sync_updated_count']}, "
        f"untouched={health_state['last_sync_untouched_count']}, "
        f"skipped={health_state['last_sync_skipped_count']}"
    )

@bot.command(name="lookup_soul")
async def lookup_soul_command(ctx: commands.Context, soul_id: str):
    if not isinstance(ctx.author, discord.Member) or not is_admin_member(ctx.author):
        await ctx.reply("You do not have permission to run this command.")
        return

    try:
        load_sheet_cache()
        row = get_cached_row_by_soul_id(soul_id)
        if row is None:
            await ctx.reply("Soul ID not found.")
            return

        await ctx.reply(
            f"soul_id={row['soul_id']}\n"
            f"full_name={row['full_name']}\n"
            f"email={row['email']}\n"
            f"discord_user_id={row['discord_user_id']}\n"
            f"discord_username={row['discord_username']}\n"
            f"projects={row['projects']}\n"
            f"active={row['active']}"
        )
    except Exception as exc:
        await ctx.reply(f"Lookup failed: {exc}")

@bot.command(name="lookup_member")
async def lookup_member_command(ctx: commands.Context, discord_user_id: str):
    if not isinstance(ctx.author, discord.Member) or not is_admin_member(ctx.author):
        await ctx.reply("You do not have permission to run this command.")
        return

    try:
        load_sheet_cache()
        row = sheet_cache_by_discord_id.get(discord_user_id.strip())
        if row is None:
            await ctx.reply("No linked member found for that Discord user ID.")
            return

        await ctx.reply(
            f"soul_id={row['soul_id']}\n"
            f"full_name={row['full_name']}\n"
            f"email={row['email']}\n"
            f"discord_user_id={row['discord_user_id']}\n"
            f"discord_username={row['discord_username']}\n"
            f"projects={row['projects']}\n"
            f"active={row['active']}"
        )
    except Exception as exc:
        await ctx.reply(f"Lookup failed: {exc}")

@bot.command(name="helpme")
async def helpme_command(ctx: commands.Context):
    await ctx.reply(
        "Commands:\n"
        "`!link SOUL_ID` -> link your Soul ID\n"
        "`!sync_now` -> admin only, run sync now\n"
        "`!sync_status` -> admin only, show sync status\n"
        "`!lookup_soul SOUL_ID` -> admin only\n"
        "`!lookup_member DISCORD_USER_ID` -> admin only"
    )

# ----------------------------
# Periodic sync
# ----------------------------
@tasks.loop(seconds=SYNC_INTERVAL_SECONDS)
async def periodic_sync():
    try:
        result = await run_full_sync()
        logger.info(result)
    except Exception as exc:
        health_state["last_sync_ok"] = False
        health_state["last_sync_message"] = str(exc)
        logger.exception("Periodic sync failed: %s", exc)

@periodic_sync.before_loop
async def before_periodic_sync():
    await bot.wait_until_ready()

# ----------------------------
# Health server
# ----------------------------
async def healthz(request):
    return web.json_response({
        "ok": True,
        "bot_ready": health_state["bot_ready"],
        "last_sync_ok": health_state["last_sync_ok"],
        "message": health_state["last_sync_message"],
        "updated": health_state["last_sync_updated_count"],
        "untouched": health_state["last_sync_untouched_count"],
        "skipped": health_state["last_sync_skipped_count"],
    })

async def readyz(request):
    ready = health_state["bot_ready"] and health_state["last_sync_ok"]
    status = 200 if ready else 503
    return web.json_response({
        "ready": ready,
        "message": health_state["last_sync_message"],
    }, status=status)

async def start_health_server():
    app = web.Application()
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/readyz", readyz)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logger.info("Health server running on port %s", PORT)

# ----------------------------
# Main
# ----------------------------
async def main():
    async with bot:
        await start_health_server()
        await bot.start(DISCORD_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())