# Connecting to the Shared (Remote) Database — Analyst Guide

This guide is for **analysts** who have been asked to point the Analyst Tool at a
shared team database. Your administrator has already set up the PostgreSQL server;
you just need to plug in the connection details.

Connecting to the shared database means:

- **You save API calls.** If a teammate already looked up an indicator within the
  last 7 days, you get their stored result instantly instead of spending one of
  your VirusTotal/AbuseIPDB/Shodan/OTX API credits.
- **You see when others are working the same indicator.** If more than one analyst
  has checked an indicator recently, the report shows a notice like
  `*** MULTI-USER NOTICE: 3 users have checked this IP in the last 7 days …`.

---

## What you need from your administrator

Ask your admin for these five values (and which network/VPN you must be on):

| Item | Example | Goes in config as |
|------|---------|-------------------|
| Server host / IP | `db.internal.example.com` | `host` |
| Port | `5432` | `port` |
| Database name | `analyst_tool` | `dbname` |
| Application DB user | `analyst_app` | `db_user` |
| Application DB password | (provided by admin) | `password` |

You also choose **your own analyst name** (e.g. `bob`, `alice`) — this is *not* the
database login; it's just a label so the "who has checked this" notice is
meaningful. Pick something unique to you and keep it consistent.

> You connect with the **same** `db_user`/`password` as everyone on the team — that
> is the shared application login. Your personal identity is the separate `user`
> field.

---

## Step 1 — Install the tool and the PostgreSQL driver

From the Analyst Tool folder:

```bash
pip install -r requirements.txt
```

This includes `psycopg2-binary`, which is required to talk to PostgreSQL. If you
ever see a "psycopg2 not found" message, install it directly:

```bash
pip install psycopg2-binary
```

---

## Step 2 — Edit the `[CACHE]` section of `config.ini`

Open `config.ini` in the Analyst Tool folder and set the `[CACHE]` section to use
the **remote** backend with the values from your admin. Fill in your own `user`:

```ini
[CACHE]
enabled = true
backend = remote
freshness_days = 7
force_prefix = !
purge_days = 0
user = bob                       ; <-- YOUR unique analyst name
check_window_days = 7
check_dedup_minutes = 60
host = db.internal.example.com   ; from admin
port = 5432                      ; from admin
dbname = analyst_tool            ; from admin
db_user = analyst_app            ; from admin (the shared DB login)
password = the-password-from-admin
sslmode = prefer                 ; use 'require' if your admin mandates TLS
```

What each field means:

- `backend = remote` — this is the switch that makes the tool use the shared
  PostgreSQL database instead of a local file. **This is the key change.**
- `user` — your personal label for the check log. Make it unique to you.
- `host`, `port`, `dbname`, `db_user`, `password` — the connection details from
  your admin. Note the connection login is `db_user`; the `user` line above is your
  identity, not a database account.
- `sslmode` — `prefer` works in most setups; use `require` if your admin runs TLS
  and wants it enforced.
- Leave `freshness_days`, `check_window_days`, and `check_dedup_minutes` at the
  defaults unless your admin tells you otherwise (keeping them consistent across
  the team is best).

> Keep your `config.ini` private — it contains the shared database password. Don't
> commit it to a public repo.

---

## Step 3 — Test the connection

Start the tool the way you normally do:

- **Terminal:** `python analyst_tool.py`
- **Jupyter:** open `Analyst Tool.ipynb`, run `from analyst import *` then `analyst()`

On a **successful** connection you'll see a line near the top like:

```
Cache enabled as user 'bob' (1284 entries). API calls saved so far: 4127.
```

The entry count and "API calls saved" reflect the **whole team's** shared database —
seeing a non-zero number confirms you're connected to the shared server.

If the tool **can't reach** the database you'll instead see something like:

```
Cache: could not initialize remote backend (… connection refused …). Caching disabled.
```

That message means the tool fell back to live lookups so you can keep working — it
won't crash — but you're not yet sharing the cache. See Troubleshooting below.

### Optional: test the connection directly

If you want to confirm connectivity independently of the tool:

```bash
python -c "import psycopg2; psycopg2.connect(host='db.internal.example.com', port=5432, dbname='analyst_tool', user='analyst_app', password='THE-PASSWORD', sslmode='prefer'); print('Connection OK')"
```

`Connection OK` means your credentials and network path are good.

---

## Step 4 — Use it normally

Nothing changes in how you work — copy an IP, hash, domain, or URL and the report
appears. With the shared database:

- A result a teammate already fetched shows a dim marker and spends **no** API call:

  ```
  IP Analysis Report for 8.8.8.8:
      (cached result — 2 days old, 6 lookups)
  ```

- When several analysts have looked at the same indicator recently, you'll see the
  heads-up notice at the top of the report:

  ```
  *** MULTI-USER NOTICE: 3 users have checked this IP in the last 7 days (5 checks total).
  ```

- Need a guaranteed-fresh result (e.g. to confirm something changed)? Copy the
  indicator with a `!` in front to bypass the cache for that one lookup:
  `!8.8.8.8`.

---

## Network requirements

You must be able to reach the database server on its port (default `5432`):

- Be on the **allowed network** your admin specified — often the office LAN or a
  **VPN**. If you're remote, connect to the VPN first.
- Corporate firewalls may block outbound `5432`; if so, ask your admin/IT.

---

## Troubleshooting

**`Cache: could not initialize remote backend … Caching disabled.`**
The tool couldn't connect, so it's running live (no sharing). Work through:

1. Are you on the required network/VPN? Try the direct `psycopg2` test above.
2. Double-check `host`, `port`, `dbname`, `db_user`, `password` for typos.
3. Confirm your machine's IP is within the range your admin allowed (`pg_hba`).
4. If your admin enforces TLS, set `sslmode = require`.

**`psycopg2` not found / module error.**
Run `pip install psycopg2-binary`.

**`password authentication failed for user "analyst_app"`.**
The password is wrong or was rotated. Get the current one from your admin.

**`no pg_hba.conf entry for host …`.**
Your IP isn't in the allowed range. Send your admin the IP you're connecting from
(and confirm you're on the right VPN/subnet).

**It connects but I never see the multi-user notice.**
That's normal until more than one qualifying check exists within the window.
Confirm every analyst set a **unique** `user`, and remember a re-check by the same
person within `check_dedup_minutes` (default 60) isn't counted again.

**I want to go back to a personal/local cache.**
Set `backend = local` (uses a local file) or `enabled = false` (no caching at all).

---

## Quick reference — what you set

| Key | You set it to |
|-----|---------------|
| `backend` | `remote` |
| `user` | your unique analyst name |
| `host`, `port`, `dbname`, `db_user`, `password` | the values your admin gave you |
| `sslmode` | `prefer` (or `require` if told to) |
| everything else | leave at the defaults |
