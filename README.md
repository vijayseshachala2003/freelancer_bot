# Freelancer Bot — Discord verification (`bot_verifier.py`)

A single-process Discord bot that enforces **verify-before-access** for a configured set of **managed access** roles. It reads **`allocations`** in **PostgreSQL** to decide **who may verify** and **which** roles each person gets from the **`projects`** column (comma / semicolon / slash / pipe separated tokens). **`MANAGED_ACCESS_ROLE_NAMES`** in `bot_verifier.py` is the **whitelist** of Discord role names the bot may assign; optional **`PROJECT_ROLE_ALIASES`** maps short DB tokens to those names. Any other managed role on the member is removed on sync/revoke/gate.

## Verification flow (intended)

1. **Add a row** to **`allocations`** with at least **`email`** and **`projects`**. Other columns use table defaults (`active=true`, `status=ACTIVE` unless you changed the schema).
2. **User joins** the server → the bot **removes** managed access roles and **gates** them (e.g. **Unverified**), then **DMs** them with **Verify now** (users must allow DMs from server members / the bot).
3. In the DM (or from **`!helpme`** in the server), they tap **Verify now** and enter the **same email** as **`allocations.email`**.
4. The bot **matches** that input to **`allocations.email`** (comparison is normalized: case-insensitive, all whitespace removed) and **assigns Discord roles** from **`allocations.projects`** (via the whitelist and optional aliases in code).

There is **no** Discord-username field on allocations: verification is **only** via the **Verify now** modal (and compliance rules for already-verified users).

## Features

- **Verify-first gating:** Users get the configured **Unverified** role until they complete verification. Managed access roles (see `MANAGED_ACCESS_ROLE_NAMES` in code) are removed on join, failed checks, revoke, and timeout until the user is verified.
- **Staff exempt roles:** Members with any role in **`VERIFICATION_EXEMPT_ROLE_NAMES`** (in `bot_verifier.py`, e.g. Admin, Support, managers) are treated as **automatically exempt**: marked in the DB as `verification_status=exempt`, never gated or stripped by compliance, and **not** resynced from `allocations` (their Discord roles stay as you set them). They do not need the Verify modal.
- **Modal verification (DM-first):** The bot **DMs** pending users with **Verify now**; if that fails (**Forbidden** / network), it **@mentions** them in **`#verify-yourself`** or the server **system channel** with the same button. The modal collects **Deccan-associated email** (also from **`!helpme`** in a channel). The bot matches input to **`allocations.email`**.
- **Role sync from DB `projects`:** After verify (and on resync while the allocation row is still valid), the bot applies only the tokens in that row’s **`allocations.projects`** (each must resolve to a name in **`MANAGED_ACCESS_ROLE_NAMES`**, or use **`PROJECT_ROLE_ALIASES`**). Any other managed role on the member is **removed**. To change a user’s access, edit their **`projects`** text in Postgres; next verify/resync applies.
- **`#verify-yourself` (optional):** The bot does not auto-post a panel; it uses this channel (if present) as **fallback** when a user cannot be **DM**'d. Create the channel and grant the bot **Send Messages**; otherwise the **system channel** is tried.
- **Compliance:** A **full guild audit** runs on startup (if enabled) and **every 30 minutes**—every member is checked against the database. A scoped admin command **`!audit_bluebird`** only processes members who currently hold at least one managed access role.
- **Revoke pipeline:** Rows with `access_revoked = true` are polled and applied in Discord; admin **`!revoke_access`** clears access and re-notifies the member.
- **HTTP health server:** Listens on `PORT` (default `8080`) for `GET /healthz` and `GET /readyz` (useful on Render and similar hosts).
- **Verification invite audit (optional):** `VERIFY_YOURSELF_TRIGGER_LOG` logs each successful delivery (**DM** or **`#verify-yourself` / system-channel** fallback if DMs are blocked). **`verification_invite_dm_ok`** in the DB records DM success; the **30-minute compliance** pass re-calls invites when it strips managed roles (retries **transient** DM errors; **Forbidden** keeps failing until the user allows DMs or uses the public fallback). After bot **connect**, a sweep re-tries DMs for pending users past **`VERIFICATION_DM_RETRY_COOLDOWN_MINUTES`**.

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

Copy `env.example` to `.env` in the project root (loaded by `python-dotenv`). Required and common variables:

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
| `VERIFY_YOURSELF_TRIGGER_LOG` | No | Default `verify_yourself_triggers.log`: append one **JSON line** per successful invite (**`delivery`**: `dm` or `channel_fallback`). Set to empty, `false`, `off`, `none`, or `0` to disable. |
| `VERIFICATION_DM_RETRY_COOLDOWN_MINUTES` | No | Default `20`: minimum minutes since last invite attempt before **`on_ready`** re-tries a **DM** for users with `verification_invite_dm_ok = false`. |
| `VERIFY_CHANNEL_RESTRICT_TO_UNVERIFIED` | No | Reserved; the bot no longer auto-edits `#verify-yourself` (DM-first; fallback may post there). |

\*Either `DATABASE_URL` or `SUPABASE_DB_HOST` + `SUPABASE_DB_PASSWORD` must be set.

### Managed access roles (not in `.env`)

Edit the tuple **`MANAGED_ACCESS_ROLE_NAMES`** near the top of `bot_verifier.py`. Each entry must be the **exact** Discord role name. The tuple must be non-empty at startup. Only these names may be assigned from **`allocations.projects`**; add new Discord roles here before using them in Postgres.

Edit **`PROJECT_ROLE_ALIASES`** in the same file if you store short tokens in **`projects`** (e.g. `BB` → `BB_Access`); every **value** must appear in **`MANAGED_ACCESS_ROLE_NAMES`**.

Edit **`VERIFICATION_EXEMPT_ROLE_NAMES`** in the same file for staff who skip verification (exact role names).

## Database

On connect, the bot runs `init_schema()` and ensures tables exist (and applies light migrations):

- **`allocations`** — Primary key `email`; **`projects`** (text: tokens separated by **`,` `;` `/` `|`**), `active`, `status` (e.g. ACTIVE / REVOKE / BAN), optional `full_name`, timestamps. On upgrade, the bot **drops** `discord_email` if it existed (verification is email-only via the modal).
- **`discord_user_verification`** — One row per Discord user ID; verification state, `assigned_projects` / `assigned_roles` JSON (snapshots for display / fallback resync), `access_revoked`, `status` (VERIFIED / NOT_VERIFIED), **`verification_invite_dm_ok`** (whether the last invite was delivered by **DM**), **`verification_invite_last_attempt_at`** (for reconnect / cooldown retries), etc.

Each token in **`projects`** must map to a Discord role name in **`MANAGED_ACCESS_ROLE_NAMES`** (or via **`PROJECT_ROLE_ALIASES`**).

## Running the bot

From the directory that contains `.env` and `bot_verifier.py`:

```bash
python3 bot_verifier.py
```

The process starts the aiohttp health server, connects to Postgres, registers persistent **Verify now** UI, and logs in to Discord.

## Discord server setup (summary)

- Create roles: **Unverified**, managed access roles (e.g. `BB_Access`), and **Admin** (or your configured names).
- **Bot role** must be **above** managed access roles in the hierarchy and needs **Manage Roles** (and to post in the **status** channel if configured). Verification uses **DMs** — remind members to allow **direct messages** from server members (or the bot) in **Privacy & Safety**.
- Optional: a manual **`#verify-yourself`** channel for FAQs; the bot does not auto-manage it.
- Gate content channels/categories: deny **Unverified** view where appropriate; allow managed access roles.
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

- **`verification_compliance_loop`:** Every **30 minutes**, full guild compliance pass (quiet status channel by default).
- **`timeout_cleanup_loop`:** Every **1 minute**, users past `VERIFICATION_TIMEOUT_HOURS` in a stale unverified state are gated and timed out in DB; status channel message on timeout if configured.
- **`revoke_poll_loop`:** Every **1 minute**, applies pending `access_revoked` flags.

Verification **DMs** with the **Verify now** button are sent on join (normal path), when compliance **strips** managed roles from someone not verified, on scoped audit in the same situation, and when admins reset or revoke access—not on every scheduled pass for every pending user with no access roles.

## HTTP endpoints

| Path | Meaning |
|------|---------|
| `/healthz` | JSON `{ "ok": true, "bot_user": "..." }` |
| `/readyz` | `200` if the bot gateway is ready, else `503` |

## License / project layout

This repository is currently centered on **`bot_verifier.py`** as the runnable entrypoint. Add your own license file if you distribute the bot.
