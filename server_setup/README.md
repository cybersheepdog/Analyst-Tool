# Server setup — Analyst Tool remote cache (PostgreSQL)

Automation for standing up the shared PostgreSQL database used by the remote
cache and multi-user check tracking. After this runs, each analyst just sets
`[CACHE] backend = remote` in their `config.ini` (the script prints the exact
block to use).

## Files

| File | Purpose |
|------|---------|
| `setup_remote_db.sh` | One-shot, idempotent setup for **Debian/Ubuntu** servers. |
| `schema.sql` | Portable SQL (role, database, tables, grants) for manual setup or other platforms. |

## Quick start (Debian/Ubuntu)

Copy this folder to the database server and run as root:

```bash
sudo ./setup_remote_db.sh --allow-cidr 10.0.0.0/24
```

That single command will:

1. Install PostgreSQL via `apt` if it isn't already present.
2. Create the `analyst_tool` database and the `analyst_app` login role
   (with a strong auto-generated password, printed once at the end).
3. Create the `indicator_cache` and `indicator_checks` tables, indexes, and grants.
4. Enable remote access: set `listen_addresses` (via `ALTER SYSTEM`) and append a
   `pg_hba.conf` rule for `10.0.0.0/24` (a timestamped backup is made first).
5. Open the PostgreSQL port in `ufw` if the firewall is active.
6. Restart PostgreSQL and verify the `analyst_app` role can log in over TCP.
7. Print the ready-to-paste `[CACHE]` configuration block.

Re-running the script is safe — it detects an existing database, role, and
`pg_hba` rule and reuses them (it will refresh the role's password).

## Options

```
--db NAME            Database name            (default: analyst_tool)
--app-user NAME      Application login role   (default: analyst_app)
--password PASS      App role password        (default: auto-generated)
--allow-cidr CIDR    Network allowed to connect, e.g. 10.0.0.0/24
                     (default: auto-detected /24 of the primary interface)
--port PORT          PostgreSQL port          (default: 5432)
--listen ADDR        listen_addresses value   (default: *)
--auth METHOD        pg_hba auth method       (default: scram-sha-256)
--no-install         Do not apt-install PostgreSQL
--no-network         Only create DB/role/schema; skip network config + restart
-h, --help           Show help
```

### Examples

```bash
# Typical: open to an office subnet, generate a password
sudo ./setup_remote_db.sh --allow-cidr 192.168.10.0/24

# Use a chosen password and custom names
sudo ./setup_remote_db.sh --allow-cidr 10.20.0.0/16 \
     --db ti_cache --app-user ti_app --password 'S3cr3t-...'

# Database objects only — you manage listen_addresses/pg_hba/firewall yourself
sudo ./setup_remote_db.sh --no-network
```

## What it changes on the server

- **PostgreSQL settings** via `ALTER SYSTEM` (written to `postgresql.auto.conf`):
  `password_encryption`, `listen_addresses`, `port`.
- **`pg_hba.conf`**: one appended `host ... scram-sha-256` line for your CIDR.
  The original is backed up to `pg_hba.conf.bak.<timestamp>` first.
- **Firewall**: a `ufw allow` rule for the port (only if `ufw` is active).
- **Service**: a `systemctl restart postgresql` to apply network settings.

To roll back the network change, restore the `pg_hba.conf.bak.*` file, run
`ALTER SYSTEM RESET listen_addresses;`, and restart PostgreSQL.

## Manual / non-Debian setup

Use `schema.sql`:

```bash
# As a superuser, create the role + database (edit the password first):
sudo -u postgres psql -f schema.sql

# Then create the schema/grants inside the new database:
sudo -u postgres psql -d analyst_tool -f schema.sql
```

Then enable remote access (section 3 of `schema.sql`) and restart PostgreSQL.

## Security notes

- The app role is the least-privileged login that owns only its two tables.
- Passwords are stored as SCRAM-SHA-256 hashes and never written to disk by the
  script (the generated password is printed once — store it in a secret manager).
- Prefer the narrowest `--allow-cidr` that covers your analysts, and set
  `sslmode = require` in the analysts' config if the server has TLS configured.
