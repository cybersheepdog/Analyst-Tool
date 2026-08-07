-- Analyst Tool — portable PostgreSQL schema for the shared remote cache.
--
-- Use this if you prefer to set things up by hand, on a non-Debian OS, or with
-- your own provisioning tooling. The setup_remote_db.sh script applies the same
-- objects automatically on Debian/Ubuntu.
--
-- Run the role/database section as a PostgreSQL superuser (e.g. `postgres`),
-- then run the schema/grants section connected to the new database.
--
-- The application also creates these tables on first run (CREATE TABLE IF NOT
-- EXISTS), so pre-creating them here is optional but lets you grant precise
-- privileges up front.

-- ===================================================================
-- 1) Role + database  (run as a superuser, connected to any database)
-- ===================================================================
-- Replace 'CHANGE_ME' with a strong password before running.

-- Store passwords as SCRAM hashes (default on PG 14+; set explicitly to be safe).
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SELECT pg_reload_conf();

-- Create the application login role if it does not already exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analyst_app') THEN
        CREATE ROLE analyst_app LOGIN PASSWORD 'CHANGE_ME';
    END IF;
END
$$;

-- Create the database (CREATE DATABASE cannot run inside DO/transaction blocks,
-- so this is a plain statement; it errors harmlessly if the DB already exists).
CREATE DATABASE analyst_tool OWNER analyst_app;

-- ===================================================================
-- 2) Schema + grants  (run connected to the analyst_tool database)
--    psql:  \connect analyst_tool
-- ===================================================================

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

-- Shared API keys, so a team keeps its keys in one place instead of pasting
-- them into every analyst's local config.ini. The application overlays these
-- (remote-first, local-fallback) onto the local config for a fixed whitelist
-- of API-key options only; access is gated by the analyst_app DB login.
CREATE TABLE IF NOT EXISTS shared_config (
    section     TEXT NOT NULL,
    option      TEXT NOT NULL,
    value       TEXT,
    updated_at  DOUBLE PRECISION,
    updated_by  TEXT,
    PRIMARY KEY (section, option)
);

GRANT USAGE, CREATE ON SCHEMA public TO analyst_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO analyst_app;
ALTER TABLE indicator_cache  OWNER TO analyst_app;
ALTER TABLE indicator_checks OWNER TO analyst_app;
ALTER TABLE shared_config    OWNER TO analyst_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO analyst_app;

-- ===================================================================
-- 2a) OPTIONAL hardening — least privilege for the shared API keys
-- ===================================================================
-- By default analyst_app owns shared_config and can both read and write it,
-- which is fine for a small trusted team. To reduce blast radius, give analysts
-- READ-ONLY access to the keys and reserve writes for a separate admin login
-- used only to run `analyst_tool_shared_config.py`. Analysts still keep full
-- read/write on the cache/checks tables they need.
--
-- Run this block as a superuser (or the current owner) if you want the split.
-- It is safe to skip; nothing in the app requires it.
--
--   -- 1) A dedicated admin login for managing keys (choose a strong password):
--   DO $$
--   BEGIN
--       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analyst_admin') THEN
--           CREATE ROLE analyst_admin LOGIN PASSWORD 'CHANGE_ME_ADMIN';
--       END IF;
--   END $$;
--
--   -- 2) Hand shared_config to the admin and make analysts read-only on it:
--   ALTER TABLE shared_config OWNER TO analyst_admin;
--   REVOKE INSERT, UPDATE, DELETE ON shared_config FROM analyst_app;
--   GRANT  SELECT                  ON shared_config TO   analyst_app;
--   GRANT  SELECT, INSERT, UPDATE, DELETE ON shared_config TO analyst_admin;
--
-- Then run the key-management commands with the admin credentials (point a
-- config.ini's [CACHE] db_user/password at analyst_admin), and give analysts
-- only the analyst_app credentials. Combine this with envelope encryption
-- (set ANALYST_SHARED_KEY) so even a leaked read-only login or backup exposes
-- only ciphertext.

-- ===================================================================
-- 3) Remote access  (edit files on the server, then restart PostgreSQL)
-- ===================================================================
-- a) Allow the server to listen on the network:
--      ALTER SYSTEM SET listen_addresses = '*';
--      ALTER SYSTEM SET port = 5432;
--    (a RESTART is required for listen_addresses/port to take effect)
--
-- b) Add a client-auth rule to pg_hba.conf (path: SHOW hba_file;):
--      host    analyst_tool    analyst_app    10.0.0.0/24    scram-sha-256
--
-- c) Open the firewall for the PostgreSQL port (e.g. 5432) to your subnet.
--
-- d) Restart PostgreSQL:  systemctl restart postgresql
