# Admin Guide — Setting Up the Remote Server with `setup_remote_db.sh`

This is the administrator's runbook for standing up the shared PostgreSQL database
that powers the Analyst Tool's remote cache and multi-user check tracking, using
the provided automation script. Follow it top to bottom.

**Audience:** the person who administers the database server. Analysts get the
separate `ANALYST_REMOTE_DB_GUIDE.md`.

**What you'll end up with:** one PostgreSQL server holding two tables
(`indicator_cache`, `indicator_checks`), a least-privileged application login that
all analysts share, network access locked to your chosen subnet, and a ready-to-
distribute `[CACHE]` config block.

---

## 1. Prerequisites

- A **Debian or Ubuntu** server you control (the script targets apt-based systems).
- **root / sudo** on that server.
- The server is reachable by your analysts — on the office LAN or a VPN. Decide the
  **CIDR** they'll connect from (e.g. `10.0.0.0/24`); you'll pass it to the script.
- Outbound/inbound TCP on the PostgreSQL port (default `5432`) is allowed between
  analysts and the server (firewall/security groups).

PostgreSQL itself does **not** need to be pre-installed — the script installs it if
it's missing.

---

## 2. Copy the setup files to the server

From this project, copy the whole `server_setup/` folder to the database server,
e.g.:

```bash
scp -r server_setup/ youruser@db-server:/tmp/server_setup
ssh youruser@db-server
cd /tmp/server_setup
chmod +x setup_remote_db.sh
```

The folder contains:

| File | Purpose |
|------|---------|
| `setup_remote_db.sh` | The automation script (run this). |
| `schema.sql` | Portable SQL, for manual/non-Debian setup. |
| `README.md` | Flag reference. |

---

## 3. Run the script

The typical invocation — open access to your analysts' subnet and let the script
generate a strong password:

```bash
sudo ./setup_remote_db.sh --allow-cidr 10.0.0.0/24
```

Common variants:

```bash
# Choose your own names and password
sudo ./setup_remote_db.sh --allow-cidr 192.168.10.0/24 \
     --db ti_cache --app-user ti_app --password 'Strong-Passphrase-Here'

# Database objects only — you'll configure listen_addresses/pg_hba/firewall yourself
sudo ./setup_remote_db.sh --no-network

# PostgreSQL already installed and managed elsewhere
sudo ./setup_remote_db.sh --allow-cidr 10.20.0.0/16 --no-install
```

### All options

| Flag | Default | Meaning |
|------|---------|---------|
| `--db NAME` | `analyst_tool` | Database name |
| `--app-user NAME` | `analyst_app` | Shared application login role |
| `--password PASS` | auto-generated | App role password |
| `--allow-cidr CIDR` | auto-detected /24 | Network allowed to connect |
| `--port PORT` | `5432` | PostgreSQL port |
| `--listen ADDR` | `*` | `listen_addresses` value |
| `--auth METHOD` | `scram-sha-256` | `pg_hba` auth method |
| `--no-install` | — | Don't apt-install PostgreSQL |
| `--no-network` | — | Skip `listen_addresses`/`pg_hba`/firewall/restart |
| `-h, --help` | — | Show help |

The script is **idempotent** — re-running it detects an existing database, role,
and `pg_hba` rule and reuses them (re-running refreshes the role password).

---

## 4. What the script does (so you know what changed)

1. **Installs PostgreSQL** via apt if `psql` isn't found (unless `--no-install`).
2. **Generates a password** if you didn't pass `--password`, and sets
   `password_encryption = scram-sha-256` so it's stored as a SCRAM hash.
3. **Creates the role** (`LOGIN`) and **database** (owned by that role), idempotently.
4. **Creates the schema**: `indicator_cache`, `indicator_checks`, their indexes, and
   grants; the two tables are owned by the app role.
5. **Configures network access** (unless `--no-network`):
   - `ALTER SYSTEM SET listen_addresses` and `port` (written to
     `postgresql.auto.conf` — no hand-editing of `postgresql.conf`).
   - Appends one `host … scram-sha-256` line to `pg_hba.conf` for your CIDR, after
     backing the file up to `pg_hba.conf.bak.<timestamp>`.
   - Adds a `ufw` allow rule if `ufw` is active.
   - **Restarts** PostgreSQL (required for `listen_addresses`/`port`).
6. **Verifies** the schema over the local socket and attempts an app-login over TCP.
7. **Prints the `[CACHE]` block** for analysts, with the server's detected IP.

---

## 5. Capture the output

At the end the script prints something like:

```
[+] Server-side setup complete.

[CACHE]
enabled = true
backend = remote
user = CHANGE_ME_PER_ANALYST
host = 10.0.0.12
port = 5432
dbname = analyst_tool
db_user = analyst_app
password = 7Qd2N8w...
sslmode = prefer
```

- **Save the password now** — if it was auto-generated it is shown **once** and is
  not stored anywhere else. Put it in your team's secret manager.
- Note the printed `host`; if the server has multiple interfaces, substitute the
  address your analysts should actually use.

---

## 6. Distribute to analysts

Give each analyst:

1. The connection values: `host`, `port`, `dbname`, `db_user`, and the `password`
   (share the password over a secure channel, not plain email/chat).
2. A unique **analyst name** to put in their `user =` field (e.g. `bob`, `alice`) —
   this drives the "X users have checked this" notice. The `db_user`/`password` are
   shared; only `user` differs per person.
3. The **`ANALYST_REMOTE_DB_GUIDE.md`**, which walks them through installing the
   driver, editing `[CACHE]`, and testing their connection.

---

## 6a. (Optional) Store shared API keys centrally

Instead of every analyst pasting the same API keys into their local
`config.ini`, you can store them once in the database. Analysts on the remote
backend then load them automatically (remote-first, with their local values as
fallback). This uses a `shared_config` table, created automatically on first use
(and included in `schema.sql`).

Run these from any machine that can reach the database and has the `[CACHE]`
credentials set in its `config.ini`:

```bash
# Push the keys already in your local config.ini up to the database:
python analyst_tool_shared_config.py import-local

# Or set individual keys explicitly:
python analyst_tool_shared_config.py set VIRUS_TOTAL x-apikey <APIKEY>
python analyst_tool_shared_config.py set ABUSE_IP_DB key <APIKEY>
python analyst_tool_shared_config.py set SHODAN shodan_api_key <APIKEY>

# Review (values are masked) or remove:
python analyst_tool_shared_config.py list
python analyst_tool_shared_config.py delete SHODAN shodan_api_key
```

Only recognised credential fields are accepted: AbuseIPDB `key`, VirusTotal
`x-apikey`, AlienVault OTX `otx_api_key`, OpenCTI `opencti_api_url` /
`opencti_api_token` / `opencti_base_url`, C2Live `c2_live_url` / `c2_live_index`,
Shodan `shodan_api_key`, and CVE `nvd_api_key`. Rotating a provider key is a
one-line `set` — every analyst picks it up on their next run, no redistribution
needed.

### Securing the shared keys

By default the values are stored as **plaintext** (like the cache tables), and
PostgreSQL does not encrypt table data at rest. For sensitive keys, layer on:

1. **Encrypt in transit.** Set `sslmode = require` (or `verify-full` with the
   server CA) in every analyst's `[CACHE]` section, and make sure the server has
   TLS enabled. `prefer` can silently fall back to an unencrypted connection.

2. **Encrypt at rest (recommended).** Give every analyst the same passphrase via
   the `ANALYST_SHARED_KEY` environment variable (or a local `key_file` named in
   `[SHARED_CONFIG]`). The tool then encrypts each value (Fernet / AES) before
   storing and decrypts on read, so the database and its backups only ever hold
   ciphertext. The passphrase is never stored in the database — distribute it
   out-of-band, once. Requires `pip install cryptography`. Set the passphrase
   before running `import-local`/`set` so the values are written encrypted; run
   `list` to confirm each shows `encrypted` rather than `PLAINTEXT`.

3. **Least privilege.** Split writes from reads so a compromised analyst login
   can read the keys (needed) but can't tamper with them. See the optional
   "2a) OPTIONAL hardening" block in `server_setup/schema.sql`, which creates an
   `analyst_admin` role that owns `shared_config` and leaves `analyst_app` with
   SELECT only. Run the management commands with the admin credentials.

4. **Prefer a secrets manager for high-value keys.** If you already run Vault,
   AWS/Azure secrets manager, or similar, that remains the most secure home for
   the keys (managed encryption, per-identity access, audit, rotation). The DB
   approach trades some of that for zero extra infrastructure.

---

## 7. Verify end-to-end

From an analyst machine **inside the allowed CIDR**:

```bash
# Direct connectivity test
python -c "import psycopg2; psycopg2.connect(host='10.0.0.12', port=5432, dbname='analyst_tool', user='analyst_app', password='THE-PASSWORD', sslmode='prefer'); print('Connection OK')"
```

Then run the tool on two machines (or with two different `user` values), copy the
same public IP on each within the window, and confirm the second one shows:

```
*** MULTI-USER NOTICE: 2 users have checked this IP in the last 7 days (2 checks total).
```

---

## 8. Operations & maintenance

### Inspect usage

```sql
-- Total API calls saved across the team
SELECT SUM(cache_hits) AS calls_saved FROM indicator_cache;

-- Most-reused indicators
SELECT indicator, service, cache_hits, api_calls
FROM indicator_cache ORDER BY cache_hits DESC LIMIT 20;

-- Who checked a given indicator in the last 7 days
SELECT username, to_timestamp(checked_at) AS when_utc
FROM indicator_checks
WHERE indicator = '45.145.66.165'
  AND checked_at >= EXTRACT(EPOCH FROM now()) - 7*86400
ORDER BY checked_at DESC;
```

### Rotate the application password

Either re-run the script (idempotent — it refreshes the role password):

```bash
sudo ./setup_remote_db.sh --allow-cidr 10.0.0.0/24 --password 'NEW-PASSWORD'
```

…or do it directly and tell analysts the new value:

```bash
sudo -u postgres psql -c "ALTER ROLE analyst_app PASSWORD 'NEW-PASSWORD';"
```

### Prune old data (server-side, scheduled)

Cached entries are re-queried automatically once stale, so pruning is optional
(it just controls table growth). A nightly cron is the cleanest server-side option:

```bash
# /etc/cron.d/analyst-tool-prune  — delete cache + checks older than 30 days at 03:00
0 3 * * *  postgres  psql -d analyst_tool -c "DELETE FROM indicator_cache  WHERE updated_at < EXTRACT(EPOCH FROM now()) - 30*86400; DELETE FROM indicator_checks WHERE checked_at < EXTRACT(EPOCH FROM now()) - 30*86400;"
```

(There is also a client-side `[CACHE] purge_days`, but a server cron is more
predictable for a shared database.)

### Back up

```bash
# Nightly logical backup
pg_dump -U postgres -d analyst_tool -F c -f /var/backups/analyst_tool_$(date +\%F).dump
```

### Note on freshness / window settings

`freshness_days`, `check_window_days`, and `check_dedup_minutes` are read from each
analyst's `config.ini`, not the server. Keep them consistent across the team by
standardizing the `[CACHE]` block you hand out.

---

## 9. Security hardening

- **Narrow the CIDR.** Prefer the smallest range that covers your analysts; re-run
  with a tighter `--allow-cidr` if you opened it wide initially.
- **Enforce TLS.** If the server has TLS configured, tell analysts to set
  `sslmode = require` (and consider `hostssl` in `pg_hba.conf`).
- **Least privilege** is already in place: the app role owns only its two tables
  and has no superuser rights.
- **Protect the password.** It's stored only as a SCRAM hash on the server; the
  plaintext lives only in analysts' `config.ini` and your secret manager.
- **Firewall.** Restrict `5432` to the analyst subnet/VPN at the network layer too,
  not just `pg_hba.conf`.

---

## 10. Rollback / uninstall

Undo the network change:

```bash
# Restore the pre-change pg_hba.conf (pick the right timestamp)
sudo cp /etc/postgresql/*/main/pg_hba.conf.bak.* /etc/postgresql/<ver>/main/pg_hba.conf
sudo -u postgres psql -c "ALTER SYSTEM RESET listen_addresses;"
sudo -u postgres psql -c "ALTER SYSTEM RESET port;"
sudo systemctl restart postgresql
```

Remove the data and role entirely:

```bash
sudo -u postgres psql -c "DROP DATABASE IF EXISTS analyst_tool;"
sudo -u postgres psql -c "DROP ROLE IF EXISTS analyst_app;"
```

---

## 11. Troubleshooting (server side)

**Analysts can't connect at all.**
- Service up? `systemctl status postgresql`
- Listening on the network? `sudo -u postgres psql -c "SHOW listen_addresses;"` and
  `ss -tlnp | grep 5432` (you want `0.0.0.0:5432` or the chosen address, not just
  `127.0.0.1`). If wrong, the restart after `ALTER SYSTEM` may not have happened —
  re-run without `--no-network`.
- Firewall: confirm `5432` is open from the analyst subnet (cloud security groups +
  host firewall).

**`no pg_hba.conf entry for host …`.**
The client's IP isn't in your `--allow-cidr`. Add/adjust the rule (re-run the script
with the right CIDR) and reload: `sudo -u postgres psql -c "SELECT pg_reload_conf();"`.

**`password authentication failed`.**
Usually a SCRAM/MD5 mismatch or a stale password. The script sets
`password_encryption = scram-sha-256` before creating the role and uses a
`scram-sha-256` `pg_hba` rule; if you have legacy `md5` rules or clients, align them.
Re-running the script refreshes the password.

**The on-server verify warned about localhost login.**
That's expected if `127.0.0.1` isn't covered by a scram rule — it doesn't mean
remote analysts are blocked. Verify from an actual client in the allowed CIDR.

**Where are the logs?**
`/var/log/postgresql/postgresql-*-main.log`.

---

## Related documents

- `ANALYST_REMOTE_DB_GUIDE.md` — hand this to your analysts.
- `server_setup/README.md` — concise flag reference for the script.
- `server_setup/schema.sql` — portable SQL for manual or non-Debian setup.
- `IMPLEMENTATION_GUIDE.md` — the broader local + remote implementation reference.
