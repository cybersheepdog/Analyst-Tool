#!/usr/bin/env bash
#
# setup_remote_db.sh — Automate the server side of the Analyst Tool remote cache.
#
# Target: Debian / Ubuntu PostgreSQL server. Run as root (or with sudo).
#
# It will (idempotently):
#   1. Install PostgreSQL via apt if it isn't present (unless --no-install).
#   2. Create the database and the application login role.
#   3. Create the indicator_cache / indicator_checks tables, indexes, and grants.
#   4. Enable remote access: listen_addresses (via ALTER SYSTEM) + a pg_hba.conf
#      rule for your analysts' CIDR (with a timestamped backup).
#   5. Open the PostgreSQL port in ufw (if ufw is active).
#   6. Restart PostgreSQL and verify the app role can log in.
#   7. Print the [CACHE] block your analysts paste into config.ini.
#
# Re-running is safe: existing database/role/rules are detected and reused.
#
# Usage:
#   sudo ./setup_remote_db.sh --allow-cidr 10.0.0.0/24 [options]
#
# Options:
#   --db NAME            Database name            (default: analyst_tool)
#   --app-user NAME      Application login role   (default: analyst_app)
#   --password PASS      App role password        (default: auto-generated)
#   --allow-cidr CIDR    Network allowed to connect, e.g. 10.0.0.0/24
#                        (default: auto-detected /24 of the primary interface)
#   --port PORT          PostgreSQL port          (default: 5432)
#   --listen ADDR        listen_addresses value   (default: *)
#   --auth METHOD        pg_hba auth method       (default: scram-sha-256)
#   --no-install         Do not attempt to apt-install PostgreSQL
#   --no-network         Skip listen_addresses / pg_hba / firewall / restart
#   -h, --help           Show this help and exit
#
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
DB_NAME="analyst_tool"
APP_USER="analyst_app"
APP_PASSWORD=""
ALLOW_CIDR=""
PG_PORT="5432"
LISTEN_ADDR="*"
AUTH_METHOD="scram-sha-256"
DO_INSTALL=1
DO_NETWORK=1

# ── Pretty logging ──────────────────────────────────────────────────────────
c_info='\033[1;34m'; c_ok='\033[1;32m'; c_warn='\033[1;33m'; c_err='\033[1;31m'; c_end='\033[0m'
info() { echo -e "${c_info}[*]${c_end} $*"; }
ok()   { echo -e "${c_ok}[+]${c_end} $*"; }
warn() { echo -e "${c_warn}[!]${c_end} $*"; }
err()  { echo -e "${c_err}[x]${c_end} $*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db)          DB_NAME="$2"; shift 2;;
    --app-user)    APP_USER="$2"; shift 2;;
    --password)    APP_PASSWORD="$2"; shift 2;;
    --allow-cidr)  ALLOW_CIDR="$2"; shift 2;;
    --port)        PG_PORT="$2"; shift 2;;
    --listen)      LISTEN_ADDR="$2"; shift 2;;
    --auth)        AUTH_METHOD="$2"; shift 2;;
    --no-install)  DO_INSTALL=0; shift;;
    --no-network)  DO_NETWORK=0; shift;;
    -h|--help)     usage;;
    *) die "Unknown option: $1 (use --help)";;
  esac
done

# ── Sanity checks ───────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Please run as root (e.g. sudo $0 ...)."

# Basic identifier validation (avoid SQL identifier injection on db/role names).
valid_ident() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; }
valid_ident "$DB_NAME"  || die "Invalid --db name: $DB_NAME"
valid_ident "$APP_USER" || die "Invalid --app-user name: $APP_USER"

# ── 1. Install PostgreSQL if needed ─────────────────────────────────────────
if ! command -v psql >/dev/null 2>&1; then
  if [[ "$DO_INSTALL" -eq 1 ]]; then
    info "PostgreSQL not found — installing via apt..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-contrib
    ok "PostgreSQL installed."
  else
    die "psql not found and --no-install given. Install PostgreSQL first."
  fi
else
  info "PostgreSQL already installed ($(psql --version))."
fi

# Make sure the service is running before we talk to it.
systemctl enable --now postgresql >/dev/null 2>&1 || true

# Helper: run SQL as the postgres superuser (peer auth over the local socket).
psql_super() { sudo -u postgres psql -v ON_ERROR_STOP=1 -qtAX "$@"; }

# ── 2. Generate a password if one wasn't supplied ───────────────────────────
if [[ -z "$APP_PASSWORD" ]]; then
  APP_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
  GEN_PW=1
else
  GEN_PW=0
fi

# Ensure new passwords are stored as SCRAM hashes.
psql_super -c "ALTER SYSTEM SET password_encryption = 'scram-sha-256';" >/dev/null
psql_super -c "SELECT pg_reload_conf();" >/dev/null || true

# ── 3. Create role and database (idempotent) ────────────────────────────────
# Pass the password as a psql variable so it never appears in the process list,
# and quote it safely for SQL with quote_literal().
role_exists="$(psql_super -c "SELECT 1 FROM pg_roles WHERE rolname='${APP_USER}';")"
if [[ "$role_exists" == "1" ]]; then
  info "Role '${APP_USER}' exists — updating its password."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -qX \
    -v pw="$APP_PASSWORD" -v role="$APP_USER" <<'SQL'
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'role', :'pw') AS stmt \gset
:stmt ;
SQL
else
  info "Creating role '${APP_USER}'."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -qX \
    -v pw="$APP_PASSWORD" -v role="$APP_USER" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role', :'pw') AS stmt \gset
:stmt ;
SQL
fi
ok "Role '${APP_USER}' ready."

db_exists="$(psql_super -c "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}';")"
if [[ "$db_exists" == "1" ]]; then
  info "Database '${DB_NAME}' already exists."
else
  info "Creating database '${DB_NAME}' owned by '${APP_USER}'."
  psql_super -c "CREATE DATABASE \"${DB_NAME}\" OWNER \"${APP_USER}\";"
fi
ok "Database '${DB_NAME}' ready."

# ── 4. Schema + grants (run inside the target database) ─────────────────────
info "Creating schema and grants in '${DB_NAME}'..."
sudo -u postgres psql -v ON_ERROR_STOP=1 -qX -d "$DB_NAME" \
  -v role="$APP_USER" <<'SQL'
CREATE TABLE IF NOT EXISTS indicator_cache (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT,
    service         TEXT NOT NULL,
    payload         TEXT,
    created_at      DOUBLE PRECISION,
    updated_at      DOUBLE PRECISION,
    lookup_count    INTEGER DEFAULT 0,
    cache_hits      INTEGER DEFAULT 0,
    api_calls       INTEGER DEFAULT 0,
    PRIMARY KEY (indicator, service)
);
CREATE INDEX IF NOT EXISTS idx_indicator ON indicator_cache(indicator);

CREATE TABLE IF NOT EXISTS indicator_checks (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT,
    username        TEXT,
    checked_at      DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_checks_ind ON indicator_checks(indicator);

GRANT USAGE, CREATE ON SCHEMA public TO :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"role";
ALTER TABLE indicator_cache  OWNER TO :"role";
ALTER TABLE indicator_checks OWNER TO :"role";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"role";
SQL
ok "Schema and grants applied."

# ── 5. Network access ───────────────────────────────────────────────────────
if [[ "$DO_NETWORK" -eq 1 ]]; then
  # Auto-detect a CIDR if none supplied: primary global IPv4, widened to /24.
  if [[ -z "$ALLOW_CIDR" ]]; then
    primary_ip="$(ip -o -f inet addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1 || true)"
    if [[ -n "$primary_ip" ]]; then
      ALLOW_CIDR="$(echo "$primary_ip" | awk -F. '{printf "%s.%s.%s.0/24", $1,$2,$3}')"
      warn "No --allow-cidr given; defaulting to detected subnet ${ALLOW_CIDR}."
      warn "Re-run with --allow-cidr to restrict access more precisely."
    else
      die "Could not auto-detect a subnet. Pass --allow-cidr (e.g. 10.0.0.0/24)."
    fi
  fi

  # listen_addresses via ALTER SYSTEM (writes postgresql.auto.conf, no manual edit).
  info "Setting listen_addresses = '${LISTEN_ADDR}' and port = ${PG_PORT}."
  psql_super -c "ALTER SYSTEM SET listen_addresses = '${LISTEN_ADDR}';" >/dev/null
  psql_super -c "ALTER SYSTEM SET port = ${PG_PORT};" >/dev/null

  # pg_hba.conf: append a host rule for our DB + role + CIDR if not already there.
  HBA_FILE="$(psql_super -c 'SHOW hba_file;')"
  info "pg_hba file: ${HBA_FILE}"
  HBA_RULE="host    ${DB_NAME}    ${APP_USER}    ${ALLOW_CIDR}    ${AUTH_METHOD}"
  if grep -Eq "^[[:space:]]*host[[:space:]]+${DB_NAME}[[:space:]]+${APP_USER}[[:space:]]+${ALLOW_CIDR}[[:space:]]" "$HBA_FILE"; then
    info "pg_hba rule already present — leaving it as-is."
  else
    cp -a "$HBA_FILE" "${HBA_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    {
      echo ""
      echo "# Added by Analyst Tool setup_remote_db.sh on $(date)"
      echo "$HBA_RULE"
    } >> "$HBA_FILE"
    ok "Appended pg_hba rule: ${HBA_RULE}"
  fi

  # Firewall (best effort, only if ufw is active).
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    info "ufw active — allowing ${ALLOW_CIDR} to port ${PG_PORT}."
    ufw allow from "$ALLOW_CIDR" to any port "$PG_PORT" proto tcp >/dev/null || warn "ufw rule add failed (continuing)."
  fi

  # listen_addresses/port changes require a full restart (reload is not enough).
  info "Restarting PostgreSQL to apply network settings..."
  systemctl restart postgresql
  ok "PostgreSQL restarted."
else
  warn "--no-network given: skipped listen_addresses / pg_hba / firewall / restart."
fi

# ── 6. Verify ───────────────────────────────────────────────────────────────
# 6a) Schema check over the local socket as the superuser — always reliable.
info "Verifying schema..."
if sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -qtAX \
      -c "SELECT 'indicator_cache rows='||count(*) FROM indicator_cache;" \
      -c "SELECT 'indicator_checks rows='||count(*) FROM indicator_checks;"; then
  ok "Schema present and queryable."
else
  warn "Schema verification query failed — check the output above."
fi

# 6b) App login over TCP — best effort (localhost may not be covered by the
#     new pg_hba rule; that does not mean remote clients are blocked).
info "Verifying application login over TCP..."
if PGPASSWORD="$APP_PASSWORD" psql -h 127.0.0.1 -p "$PG_PORT" -U "$APP_USER" \
      -d "$DB_NAME" -v ON_ERROR_STOP=1 -qtAX -c "SELECT 1;" >/dev/null 2>/tmp/_at_err; then
  ok "App role '${APP_USER}' can log in over TCP."
else
  warn "Could not verify app TCP login from the server itself:"
  sed 's/^/    /' /tmp/_at_err >&2 || true
  warn "This usually just means 127.0.0.1 isn't covered by a scram rule; it does"
  warn "NOT necessarily mean remote analysts are blocked. Test from a host in ${ALLOW_CIDR}."
fi
rm -f /tmp/_at_err 2>/dev/null || true

# ── 7. Print the analysts' config block ─────────────────────────────────────
SERVER_IP="$(ip -o -f inet addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1 || echo 'YOUR.SERVER.IP')"

echo
ok "Server-side setup complete."
echo
echo "=================================================================="
echo " Give each analyst these [CACHE] settings in their config.ini"
echo " (set a UNIQUE 'user' per analyst):"
echo "=================================================================="
cat <<CFG

[CACHE]
enabled = true
backend = remote
freshness_days = 7
force_prefix = !
purge_days = 0
user = CHANGE_ME_PER_ANALYST
check_window_days = 7
check_dedup_minutes = 60
host = ${SERVER_IP}
port = ${PG_PORT}
dbname = ${DB_NAME}
db_user = ${APP_USER}
password = ${APP_PASSWORD}
sslmode = prefer

CFG
echo "=================================================================="
if [[ "$GEN_PW" -eq 1 ]]; then
  warn "The app password was auto-generated and is shown above ONCE."
  warn "Store it securely (e.g. a password manager); it is not saved anywhere else."
fi
echo
