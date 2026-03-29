# Freelancer Bot — Discord verification (`bot_verifier.py`)

A single-process Discord bot that enforces **verify-before-access** for a configured set of **managed access** roles. It reads allocations from **PostgreSQL** (including Supabase), syncs Discord roles to match `allocations.projects`, and strips roles that are not authorized by the database.

## Features

- **Verify-first gating:** Users get the configured **Unverified** role until they complete verification. Managed access roles (see `MANAGED_ACCESS_ROLE_NAMES` in code) are removed on join, failed checks, revoke, and timeout until the user is verified.
- **Modal verification:** A persistent **Verify now** button opens a modal for the user’s **Deccan-associated email**; the bot matches it to the `allocations` table (and optional `discord_email`).
- **Role sync from DB:** On success and on resync, Discord roles are aligned with `allocations.projects` tokens. Any managed access role the member has that is **not** in their current allocation is **removed** (manual invites or stale roles).
- **Channel `#verify-yourself`:** Name is fixed in code (`VERIFY_CHANNEL_NAME`). The bot posts a verify panel once if missing; verification notices and several commands attach the same **Verify now** button where possible.
<<<<<<< HEAD
- **Compliance:** A **full guild audit** runs on startup (if enabled) and **every minute**—every member is checked against the database. A scoped admin command **`!audit_bluebird`** only processes members who currently hold at least one managed access role.
=======
- **Compliance:** A **full guild audit** runs on startup (if enabled) and **every 30 minutes**—every member is checked against the database. A scoped admin command **`!audit_bluebird`** only processes members who currently hold at least one managed access role.
>>>>>>> c1561dd (updated read me file)
- **Revoke pipeline:** Rows with `access_revoked = true` are polled and applied in Discord; admin **`!revoke_access`** clears access and re-notifies the member.
- **HTTP health server:** Listens on `PORT` (default `8080`) for `GET /healthz` and `GET /readyz` (useful on Render and similar hosts).

## Requirements

- **Python 3.9+** (type hints such as `frozenset[str]` assume a recent Python).
- **Discord bot** with **Server Members Intent** and **Message Content Intent** enabled in the Developer Portal.
- **PostgreSQL** reachable with a connection string or Supabase-style host/password variables (see below).

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` includes `gspread` / `google-auth`; the current `bot_verifier.py` does not import them. They are harmless extras unless you add separate tooling.

## Configuration

<<<<<<< HEAD
Create a `.env` in the project root (loaded by `python-dotenv`). Required and common variables:
=======
Copy `env.example` to `.env` in the project root (loaded by `python-dotenv`). Required and common variables:
>>>>>>> c1561dd (updated read me file)

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_TOKEN` | Yes | Bot token. |
| `GUILD_ID` | Yes | Target server ID (numeric string). |
| `DATABASE_URL` | Yes* | PostgreSQL URI, e.g. `postgresql://user:pass@host:5432/db?sslmode=require`. |
| `SUPABASE_DB_HOST`, `SUPABASE_DB_PASSWORD` | Yes* | Alternative to `DATABASE_URL`; optional `SUPABASE_DB_PORT`, `SUPABASE_DB_USER`, `SUPABASE_DB_NAME`, `SUPABASE_DB_SSLMODE`. |
| `UNVERIFIED_ROLE_NAME` | No | Default `Unverified`. |
| `VERIFIED_ROLE_NAME` | No | Legacy Discord role removed when present; bot does not assign Verified. Default `Verified`. |
| `ADMIN_ROLE_NAME` | No | Default `Admin` (for admin-only commands). |
| `VERIFICATION_TIMEOUT_HOURS` | No | Default `24`; stale unverified users are processed by the timeout task. |
| `AUDIT_ON_STARTUP` | No | Default `true`; runs full member compliance shortly after connect. |
| `STATUS_CHANNEL_NAME` | No | If set, bot posts operational summaries (audits, timeouts, revokes) there. |
| `PORT` | No | HTTP server port; default `8080`. |
| `LOG_LEVEL` | No | Default `INFO`. |

\*Either `DATABASE_URL` or `SUPABASE_DB_HOST` + `SUPABASE_DB_PASSWORD` must be set.

### Managed access roles (not in `.env`)

Edit the tuple **`MANAGED_ACCESS_ROLE_NAMES`** near the top of `bot_verifier.py`. Each entry must be the **exact** Discord role name. The tuple must be non-empty at startup. Every token in `allocations.projects` must be listed here, or the bot will not assign that role.

## Database

On connect, the bot runs `init_schema()` and ensures tables exist (and applies light migrations):

- **`allocations`** — Primary key `email`; includes `projects` (text), `active`, `status` (e.g. ACTIVE / REVOKE / BAN), `discord_email`, timestamps.
- **`discord_user_verification`** — One row per Discord user ID; verification state, `assigned_projects` / `assigned_roles` JSON, `access_revoked`, `status` (VERIFIED / NOT_VERIFIED), etc.

The `projects` column uses separators **`,` `;` `/` `|`** between tokens. Each token is a Discord role name that must appear in `MANAGED_ACCESS_ROLE_NAMES`.

## Running the bot

From the directory that contains `.env` and `bot_verifier.py`:

```bash
python3 bot_verifier.py
```

The process starts the aiohttp health server, connects to Postgres, registers persistent **Verify now** UI, and logs in to Discord.

## Discord server setup (summary)

- Create roles: **Unverified**, managed access roles (e.g. `BB_Access`), and **Admin** (or your configured names).
- Create text channel **`verify-yourself`** (exact name unless you change `VERIFY_CHANNEL_NAME` in code).
- **Bot role** must be **above** managed access roles in the hierarchy and needs **Manage Roles** (and permissions to post in verify and status channels).
- Gate content channels/categories: deny **Unverified** view where appropriate; allow managed access roles. Allow **Unverified** on `#verify-yourself`.
- Prefer invites that do **not** auto-grant managed access roles; the bot strips them for unverified users anyway.

## Commands

Prefix is **`!`**. Built-in `help` is disabled (`help_command=None`); use **`!helpme`**.

| Command | Who | Description |
|---------|-----|-------------|
| `!helpme` | Anyone | Explains verification; includes **Verify now** in server context. |
| `!reset_verification` | Self; admins can target `@user` | Resets DB row, revokes access, sends verification notice to target. |
| `!audit_bluebird` | Admin | Scoped audit: only members with any **managed access** role. |
| `!revoke_access @member` | Admin | Hard revoke in Discord + DB; notifies member with verify UI. |
| `!kick @member` [reason] | Admin | Kicks member; sets `allocations.status` to REVOKE when allocation email is known. |
| `!ban @member` [reason] | Admin | Bans member; sets `allocations.status` to BAN when allocation email is known. |

## Background behavior

<<<<<<< HEAD
- **`verification_compliance_loop`:** Every **1 minute**, full guild compliance pass (quiet status channel by default).
- **`timeout_cleanup_loop`:** Every **1 minute**, users past `VERIFICATION_TIMEOUT_HOURS` in a stale unverified state are gated and timed out in DB; status channel message on timeout if configured.
- **`revoke_poll_loop`:** Every **1 minute**, applies pending `access_revoked` flags.

Verification **pings** with the **Verify now** button are sent on join (normal path), when compliance **strips** managed roles from someone not verified, on scoped audit in the same situation, and when admins reset or revoke access—not on every minute for every pending user with no access roles.
=======
- **`verification_compliance_loop`:** Every **30 minutes**, full guild compliance pass (quiet status channel by default).
- **`timeout_cleanup_loop`:** Every **1 minute**, users past `VERIFICATION_TIMEOUT_HOURS` in a stale unverified state are gated and timed out in DB; status channel message on timeout if configured.
- **`revoke_poll_loop`:** Every **1 minute**, applies pending `access_revoked` flags.

Verification **pings** with the **Verify now** button are sent on join (normal path), when compliance **strips** managed roles from someone not verified, on scoped audit in the same situation, and when admins reset or revoke access—not on every scheduled pass for every pending user with no access roles.
>>>>>>> c1561dd (updated read me file)

## HTTP endpoints

| Path | Meaning |
|------|---------|
| `/healthz` | JSON `{ "ok": true, "bot_user": "..." }` |
| `/readyz` | `200` if the bot gateway is ready, else `503` |

## License / project layout

This repository is currently centered on **`bot_verifier.py`** as the runnable entrypoint. Add your own license file if you distribute the bot.
