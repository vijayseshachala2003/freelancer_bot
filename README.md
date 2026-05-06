# Freelancer Bot — Discord verification (`bot_verifier.py`)

A single-process Discord bot that enforces **verify-before-access** for a configured set of **managed access** roles. It reads **`allocations`** in **PostgreSQL** to decide **who may verify** and **which** roles each person gets from the **`projects`** column (comma / semicolon / slash / pipe separated tokens). **`MANAGED_ACCESS_ROLE_NAMES`** in `bot_verifier.py` is the **whitelist** of Discord role names the bot may assign; optional **`PROJECT_ROLE_ALIASES`** maps short DB tokens to those names. Any other managed role on the member is removed on sync/revoke/gate.

## Verification flow (intended)

1. **Add a row** to **`allocations`** with at least **`email`** and **`projects`**. Other columns use table defaults (`active=true`, `status=ACTIVE` unless you changed the schema). You can also do this via the Admin Management Panel (see below).
2. **User joins** the server → the bot **removes** managed access roles and **gates** them (e.g. **Unverified**), then **DMs** them with **Verify now** (users must allow DMs from server members / the bot).
3. In the DM (or from **`!helpme`** in the server), they tap **Verify now** and enter the **same email** as **`allocations.email`**.
4. The bot **matches** that input to **`allocations.email`** (comparison is normalized: case-insensitive, all whitespace removed) and **assigns Discord roles** from **`allocations.projects`** (via the whitelist and optional aliases in code).

There is **no** Discord-username field on allocations: verification is **only** via the **Verify now** modal (and compliance rules for already-verified users).

## Features

- **Verify-first gating:** Users get the configured **Unverified** role until they complete verification. Managed access roles (see `MANAGED_ACCESS_ROLE_NAMES` in code) are removed on join, failed checks, revoke, and timeout until the user is verified.
- **Staff exempt roles:** Members with any role in **`VERIFICATION_EXEMPT_ROLE_NAMES`** (in `bot_verifier.py`, e.g. Admin, Support, managers) are treated as **automatically exempt**: marked in the DB as `verification_status=exempt`, never gated or stripped by compliance, and **not** resynced from `allocations` (their Discord roles stay as you set them). They do not need the Verify modal.
- **Modal verification (DM-first):** The bot **DMs** pending users with **Verify now**; if that fails (**Forbidden** / network), it **@mentions** them in **`#verify-yourself`** or the server **system channel** with the same button. The modal collects **Deccan-associated email** (also from **`!helpme`** in a channel). The bot matches input to **`allocations.email`**.
- **Role sync from DB `projects`:** After verify (and on resync while the allocation row is still valid), the bot applies only the tokens in that row's **`allocations.projects`** (each must resolve to a name in **`MANAGED_ACCESS_ROLE_NAMES`**, or use **`PROJECT_ROLE_ALIASES`**). Any other managed role on the member is **removed**. To change a user's access, edit their **`projects`** text in Postgres or via the Admin Panel; next verify/resync applies.
- **Admin Management Panel:** A persistent interactive UI in a private Discord channel for Admin and Support roles to manage allocations and members without touching the database directly (see below).
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
| `ADMIN_ROLE_NAME` | No | Default `Admin` (for admin-only commands and the Admin Panel). |
| `SUPPORT_ROLE_NAME` | No | Default `Support` (grants access to the Admin Management Panel alongside Admin). |
| `ADMIN_PANEL_CHANNEL_NAME` | No | Default `admin-management`. Name of the private channel where the Admin Panel is posted. Create this channel and restrict it to Admin and Support roles only. |
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

On connect, the bot runs `init_schema()` and ensures all tables exist (and applies light migrations):

### `allocations`
Primary key `email`; **`projects`** (text: tokens separated by **`,` `;` `/` `|`**), `active`, `status` (ACTIVE / REVOKE / BAN), optional `full_name`, timestamps. On upgrade, the bot **drops** `discord_email` if it existed (verification is email-only via the modal).

### `discord_user_verification`
One row per Discord user ID; verification state, `assigned_projects` / `assigned_roles` JSON (snapshots for display / fallback resync), `access_revoked`, `status` (VERIFIED / NOT_VERIFIED), **`verification_invite_dm_ok`** (whether the last invite was delivered by **DM**), **`verification_invite_last_attempt_at`** (for reconnect / cooldown retries), etc.

### `bot_settings`
Key-value store for bot runtime state that must survive Render restarts (disk is ephemeral). Currently stores:

| Key | Value |
|-----|-------|
| `admin_panel_message_id` | Discord message ID of the Admin Panel embed — used to edit the existing panel on restart instead of re-posting it. |

### `admin_audit_log`
Append-only record of every action taken through the Admin Management Panel. Every row captures who acted, what they did, and what changed.

| Column | Description |
|--------|-------------|
| `actor_discord_id` | Discord user ID of the Admin/Support who performed the action |
| `actor_username` | Their Discord username at the time of the action |
| `action` | One of: `add_user_to_role`, `remove_user_from_role`, `edit_allocation`, `reset_user`, `bulk_add` |
| `target_email` | Allocation email affected (where applicable) |
| `target_discord_id` | Discord ID of the member acted on (for `reset_user`) |
| `details` | JSONB with action-specific data (projects assigned, token removed, old/new values, bulk counts, etc.) |
| `performed_at` | Timestamp (auto-set by DB) |

Query example:
```sql
-- All recent admin actions
SELECT actor_username, action, target_email, details, performed_at
FROM admin_audit_log ORDER BY performed_at DESC LIMIT 50;

-- Everything done by a specific user
SELECT * FROM admin_audit_log WHERE actor_discord_id = '123456789' ORDER BY performed_at DESC;

-- Full history for an email
SELECT * FROM admin_audit_log WHERE target_email = 'user@example.com' ORDER BY performed_at DESC;
```

Each token in **`projects`** must map to a Discord role name in **`MANAGED_ACCESS_ROLE_NAMES`** (or via **`PROJECT_ROLE_ALIASES`**).

## Admin Management Panel

A persistent embed with interactive buttons posted in the `#admin-management` channel (configurable via `ADMIN_PANEL_CHANNEL_NAME`). Accessible only to members with the **Admin** or **Support** role. All responses are **ephemeral** — only the acting user sees them.

On bot startup, the panel is restored from `bot_settings.admin_panel_message_id` (edits the existing message). If the message no longer exists, a new one is created and its ID saved to the DB.

### Available actions

| Button | What it does |
|--------|-------------|
| **Add User to Role** | Opens a modal to enter email, role tokens, and optional full name. Upserts a row in `allocations`. If the user is already verified in the server, Discord roles are assigned immediately. Logged to `admin_audit_log`. |
| **Remove User from Role** | Opens a modal to enter email, then shows a dropdown of their current roles. Removes the selected token from `allocations.projects` and strips the Discord role from the member if present. Logged to `admin_audit_log`. |
| **View Members by Role** | Shows a dropdown of all managed roles. Returns a private embed listing all verified members who hold the selected role, with their Discord mention and email. |
| **Edit Allocation** | Opens a modal to enter an email. Shows current values, then opens a pre-filled edit modal for `projects`, `active`, and `status`. Saves changes to `allocations`. Logged to `admin_audit_log`. |
| **Reset / Re-verify User** | Shows a Discord user selector. After confirmation, resets the user's DB record, strips managed roles, adds the Unverified gate, and DMs them a new Verify now notice. Logged to `admin_audit_log`. |
| **Bulk Add Users** | Choose between **Paste List** (modal, `email,projects` one per line) or **Upload CSV** (attach a `.csv` file with `email,projects` columns). Upserts all rows in `allocations` and assigns Discord roles to already-verified members. Returns a summary of new / updated / failed. Logged to `admin_audit_log`. |

### Bulk add format

```
# Paste or CSV — header row is optional
user@example.com,BB_Access
other@example.com,maitrix-coders
third@example.com,BB_Access,AE_Access
```

Role tokens must exist in `MANAGED_ACCESS_ROLE_NAMES`.

## Running the bot

From the directory that contains `.env` and `bot_verifier.py`:

```bash
python3 bot_verifier.py
```

The process starts the aiohttp health server, connects to Postgres (running `init_schema()` to create all tables), registers persistent views (**Verify now** and **Admin Panel**), and logs in to Discord.

## Discord server setup (summary)

- Create roles: **Unverified**, managed access roles (e.g. `BB_Access`), **Admin**, and **Support** (or your configured names).
- **Bot role** must be **above** managed access roles in the hierarchy and needs **Manage Roles** (and to post in the **status** channel if configured). Verification uses **DMs** — remind members to allow **direct messages** from server members (or the bot) in **Privacy & Safety**.
- Create an **`#admin-management`** channel (or the name set in `ADMIN_PANEL_CHANNEL_NAME`). Set its permissions so **only Admin and Support roles can view and send messages** — no other roles. The bot will post the Admin Panel here on startup.
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

Note: the text commands above are **Admin-only**. Support staff should use the **Admin Management Panel** for equivalent actions.

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
