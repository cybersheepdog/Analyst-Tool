# Analyst Tool — Implementation & Setup Guide

Step-by-step instructions to set up the result cache and the multi-user check
tracking, for both a single analyst (local SQLite) and a team (shared
PostgreSQL). Follow Part A for local; add Part B for a shared team database.

If you only want to *use* the tool, see `QUICKSTART.md`. For a full feature
reference, see `USER_GUIDE.md`.

---

## What was added (file overview)

| File | Role |
|------|------|
| `analyst_tool_cache.py` | New module: the SQLite/PostgreSQL cache backends, the capture/replay logic, usage counters, and the per-user check log + multi-user notice. |
| `analyst.py` | Wired the cache in: it initializes the cache, records each check, prints the multi-user notice, and serves cached results. |
| `config.ini` | New `[CACHE]` section controls everything below. |
| `requirements.txt` | Adds `psycopg2-binary` (only needed for the remote PostgreSQL backend). |

No existing functionality changed. With `[CACHE] enabled = false`, the tool
behaves exactly as before.

### How it works in one paragraph

When you copy an IP, hash, domain, or URL, the tool first records the check
(who + when) and, for each cached service (VirusTotal, AbuseIPDB, Shodan, OTX),
looks in the database. If a stored result is younger than `freshness_days` it is
replayed and **no API call is made**; otherwise the live call runs and the result
is saved. If more than one analyst (or the same analyst in sessions more than
`check_dedup_minutes` apart) has checked that indicator within
`check_window_days`, a heads-up notice is printed.

![Multi-user notice example](graphics/screenshot_multiuser_notice.svg)

---

## Part A — Local setup (single analyst, SQLite)

This is the default and needs no database server.

### Step 1 — Install dependencies

```bash
pip install -r requirements.txt
```

(The local backend uses Python's built-in `sqlite3`, so nothing extra is strictly
required; `psycopg2-binary` is only used for Part B.)

### Step 2 — Confirm the `[CACHE]` settings in `config.ini`

The shipped defaults already enable local caching:

```ini
[CACHE]
enabled = true
backend = local
freshness_days = 7
db_path = analyst_cache.db
force_prefix = !
purge_days = 0
user =
check_window_days = 7
check_dedup_minutes = 60
```

- Leave `backend = local`.
- Optionally set `user = yourname` so the check log shows a friendly name. If you
  leave it blank, your operating-system login name is used automatically.

### Step 3 — Run the tool

Terminal:

```bash
python analyst_tool.py
```

Jupyter: open `Analyst Tool.ipynb` and run `from analyst import *` then `analyst()`.

On startup you'll see a line like:

```
Cache enabled as user 'bob' (0 entries). API calls saved so far: 0.
```

The database file (`analyst_cache.db`) and its tables are created automatically on
first run.

### Step 4 — Verify it works

1. Copy a public IP (e.g. `8.8.8.8`). You'll get a full live report.
2. Copy something else, then copy `8.8.8.8` again. The VirusTotal/Shodan/AbuseIPDB/
   OTX sections now show a dim `(cached result — … old, … lookups)` marker and no
   API call is spent.

   ![Cached result example](graphics/screenshot_cached_hit.svg)

3. To force a live refresh, copy it with the prefix: `!8.8.8.8`.

That completes the local setup.

---

## Part B — Remote setup (team, shared PostgreSQL)

Point multiple analysts at one PostgreSQL database so a lookup one person already
paid for is free for everyone, and so the "X users have checked this" notice spans
the whole team.

> **Shortcut (Debian/Ubuntu):** the whole server side below is automated by
> `server_setup/setup_remote_db.sh`. Copy the `server_setup/` folder to the
> database server and run, for example:
>
> ```bash
> sudo ./setup_remote_db.sh --allow-cidr 10.0.0.0/24
> ```
>
> It installs PostgreSQL if needed, creates the database/role/schema/grants,
> configures `listen_addresses` + `pg_hba.conf` for your CIDR (with a backup),
> opens the firewall, restarts PostgreSQL, and prints the exact `[CACHE]` block
> for your analysts. Re-running is safe. See `server_setup/README.md` for all
> options. The manual steps below explain what the script does, for other
> platforms or if you prefer to do it by hand (`server_setup/schema.sql` has the
> portable SQL).

### Step 1 — Install the PostgreSQL driver

On every analyst's machine:

```bash
pip install psycopg2-binary
```

(It's already listed in `requirements.txt`.)

### Step 2 — Create the database and a login role (once, on the server)

On the PostgreSQL server, as an admin (`psql`):

```sql
CREATE DATABASE analyst_tool;
CREATE USER analyst_app WITH PASSWORD 'choose-a-strong-password';
GRANT ALL PRIVILEGES ON DATABASE analyst_tool TO analyst_app;
```

Then connect to the new database and allow the app role to create/use tables:

```sql
\connect analyst_tool
GRANT ALL ON SCHEMA public TO analyst_app;
```

You do **not** need to create any tables — the tool creates `indicator_cache` and
`indicator_checks` automatically on first connection.

### Step 3 — Make the server reachable

Ensure the server accepts connections from your analysts:

- `postgresql.conf`: `listen_addresses = '*'` (or the appropriate interface).
- `pg_hba.conf`: add a line permitting your analysts' network, e.g.
  `host  analyst_tool  analyst_app  10.0.0.0/24  scram-sha-256`.
- Open the firewall for the PostgreSQL port (default `5432`).
- Reload PostgreSQL (`SELECT pg_reload_conf();` or restart the service).

### Step 4 — Configure each analyst's `config.ini`

On each machine, edit `[CACHE]`:

```ini
[CACHE]
enabled = true
backend = remote
freshness_days = 7
force_prefix = !
purge_days = 0
user = alice                 ; <-- unique per analyst (bob, carol, …)
check_window_days = 7
check_dedup_minutes = 60
host = db.internal.example.com
port = 5432
dbname = analyst_tool
db_user = analyst_app
password = choose-a-strong-password
sslmode = prefer             ; use 'require' to enforce TLS
```

Key points:

- `backend = remote` switches from SQLite to PostgreSQL.
- `db_user`/`password`/`host`/`dbname` are the **connection** credentials.
- `user` is the **analyst identity** recorded in the check log — give every person
  a different value so the multi-user notice is meaningful.

> Hand analysts the dedicated **`ANALYST_REMOTE_DB_GUIDE.md`** — it walks them
> through installing the driver, filling in these `[CACHE]` values, testing the
> connection, and troubleshooting, without the server-side detail.

### Step 5 — Run and verify

Start the tool on two different analysts' machines (or with two different `user`
values for a quick test). On the first machine, copy an IP — you'll get a live
report. On the second machine, copy the same IP within 7 days — you'll see the
cached result **and** a notice such as:

```
*** MULTI-USER NOTICE: 2 users have checked this IP in the last 7 days (2 checks total).
```

If the database can't be reached, the tool prints a notice and falls back to live
lookups (caching simply turns off) — it never blocks your work.

---

## Tuning the multi-user notice

| Want to… | Change |
|----------|--------|
| Widen/narrow the "recently checked" window | `check_window_days` (default 7) |
| Count quick re-checks by the same person more/less aggressively | `check_dedup_minutes` (default 60). Larger = the same user must wait longer before a re-check counts again. |
| Change the freshness window for reusing cached API results | `freshness_days` (default 7) — independent of the notice window. |
| Use a different force-refresh character | `force_prefix` (default `!`) |

---

## Inspecting the database

The two tables are plain SQL and easy to query.

Local (SQLite):

```bash
sqlite3 analyst_cache.db
sqlite> SELECT indicator, service, lookup_count, cache_hits, api_calls FROM indicator_cache ORDER BY cache_hits DESC LIMIT 10;
sqlite> SELECT indicator, username, datetime(checked_at,'unixepoch') AS when_utc FROM indicator_checks ORDER BY checked_at DESC LIMIT 20;
```

Remote (PostgreSQL):

```sql
-- Top indicators by API calls saved
SELECT indicator, service, cache_hits, api_calls
FROM indicator_cache ORDER BY cache_hits DESC LIMIT 10;

-- Total API calls saved across the team
SELECT SUM(cache_hits) AS calls_saved FROM indicator_cache;

-- Who has checked a given IP in the last 7 days
SELECT username, to_timestamp(checked_at) AS when_utc
FROM indicator_checks
WHERE indicator = '45.145.66.165'
  AND checked_at >= EXTRACT(EPOCH FROM now()) - 7*86400
ORDER BY checked_at DESC;
```

### Schema

`indicator_cache` — one row per `(indicator, service)`:

| Column | Meaning |
|--------|---------|
| `indicator`, `indicator_type` | the value and its kind (ip/hash/domain/url) |
| `service` | virustotal / abuseipdb / shodan / otx |
| `payload` | the stored result text that gets replayed |
| `created_at`, `updated_at` | epoch timestamps |
| `lookup_count`, `cache_hits`, `api_calls` | usage counters |

`indicator_checks` — one row per qualifying check:

| Column | Meaning |
|--------|---------|
| `indicator`, `indicator_type` | what was checked |
| `username` | analyst identity (`[CACHE] user` or OS login) |
| `checked_at` | epoch timestamp of the check |

---

## Verification checklist

- [ ] `pip install -r requirements.txt` completes.
- [ ] Tool starts and prints `Cache enabled as user '…'`.
- [ ] A repeated lookup shows the `(cached result …)` marker and spends no API call.
- [ ] `!<indicator>` forces a fresh lookup.
- [ ] (Remote) A second analyst/user triggers the `MULTI-USER NOTICE`.
- [ ] Setting `[CACHE] enabled = false` returns the tool to live-only behavior.

---

## Troubleshooting

**`Cache: could not initialize remote backend …`** — the PostgreSQL connection
failed. Check `host`, `port`, `dbname`, `db_user`, `password`, `sslmode`, network/
firewall, and `pg_hba.conf`. The tool falls back to live lookups until fixed.

**No multi-user notice appears.** It only fires when more than one qualifying check
exists within `check_window_days`. Confirm each analyst has a distinct `[CACHE]
user`, that they share the same remote database, and that checks are within the
window. Remember a same-user re-check within `check_dedup_minutes` is intentionally
not counted again.

**`psycopg2` not found.** Run `pip install psycopg2-binary`. It's only needed for
the remote backend.

**I want everything live (no cache).** Set `[CACHE] enabled = false`.
