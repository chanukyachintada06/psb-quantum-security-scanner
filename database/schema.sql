-- === FILE: supabase_schema.sql ===
-- ============================================================
-- QUANTUM-SAFE CRYPTOGRAPHY SCANNER — Supabase SQL Schema
-- Team CypherRed261 | PSB Hackathon 2026
-- Supabase (PostgreSQL) Compatible | Production-Ready
-- ============================================================

-- Note: Run this in the Supabase SQL Editor.
-- Supabase Auth (auth.users) is used for authentication.
-- Do NOT create a separate users table.

-- ============================================================
-- SECTION 1: ENABLE EXTENSIONS
-- ============================================================

-- Enable UUID generation (required for gen_random_uuid())
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ============================================================
-- SECTION 2: TABLE DEFINITIONS
-- ============================================================

-- ------------------------------------------------------------
-- TABLE 1: profiles
-- One-to-one with auth.users. Created on user signup.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id          UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    full_name   TEXT,
    role        TEXT        NOT NULL DEFAULT 'analyst'
                            CHECK (role IN ('admin', 'auditor', 'analyst')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  public.profiles             IS 'Extended user profile linked to Supabase Auth';
COMMENT ON COLUMN public.profiles.id          IS 'References auth.users.id — the Supabase Auth user UUID';
COMMENT ON COLUMN public.profiles.role        IS 'RBAC role: admin | auditor | analyst';

-- Auto-update updated_at on row change
CREATE OR REPLACE FUNCTION public.handle_profile_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_profiles_updated
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.handle_profile_updated_at();

-- Auto-create a profile row whenever a user signs up via Supabase Auth
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name)
    VALUES (
        NEW.id,
        NEW.email,
        NEW.raw_user_meta_data ->> 'full_name'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- ------------------------------------------------------------
-- TABLE 2: scan_results
-- Stores each TLS/PQC scan performed by a user.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_results (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    domain              TEXT        NOT NULL CHECK (char_length(domain) >= 3),
    ip_address          TEXT,
    scan_status         TEXT        NOT NULL DEFAULT 'pending'
                                    CHECK (scan_status IN ('pending', 'completed', 'failed')),
    quantum_risk_score  INTEGER     CHECK (quantum_risk_score BETWEEN 0 AND 100),
    risk_level          TEXT        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    tls_version         TEXT,                        -- e.g., TLSv1.3
    certificate_issuer  TEXT,                        -- e.g., DigiCert Inc.
    certificate_expiry  DATE,                        -- cert expiry date
    pqc_readiness_pct   NUMERIC(5,2),               -- e.g., 72.50 (%)
    scan_duration       NUMERIC(8,3),               -- seconds, e.g., 4.231
    error_message       TEXT,                        -- populated on failure
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  public.scan_results                    IS 'TLS and PQC scan results per domain per user';
COMMENT ON COLUMN public.scan_results.quantum_risk_score IS '0 = fully PQC safe, 100 = critically vulnerable';
COMMENT ON COLUMN public.scan_results.pqc_readiness_pct  IS 'Percentage of endpoints deemed PQC-ready';

CREATE OR REPLACE FUNCTION public.handle_scan_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_scan_results_updated
    BEFORE UPDATE ON public.scan_results
    FOR EACH ROW EXECUTE FUNCTION public.handle_scan_updated_at();


-- ------------------------------------------------------------
-- TABLE 3: cbom_records
-- Cryptographic Bill of Materials — one row per algorithm
-- discovered in a scan. Cascades on scan deletion.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cbom_records (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID        NOT NULL REFERENCES public.scan_results(id) ON DELETE CASCADE,
    algorithm       TEXT        NOT NULL,   -- e.g., RSA, ECC, DH, ECDSA
    key_length      INTEGER,               -- e.g., 2048, 256, 384
    cipher_suite    TEXT,                  -- e.g., TLS_AES_256_GCM_SHA384
    protocol        TEXT,                  -- e.g., TLSv1.3
    pqc_status      TEXT        NOT NULL DEFAULT 'VULNERABLE'
                                CHECK (pqc_status IN ('SAFE', 'VULNERABLE', 'HYBRID')),
    recommendation  TEXT,                  -- Migration advice
    nist_standard   TEXT,                  -- e.g., FIPS-203, FIPS-204
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  public.cbom_records              IS 'Cryptographic Bill of Materials per scan (CERT-IN Annexure-A)';
COMMENT ON COLUMN public.cbom_records.pqc_status   IS 'SAFE = PQC-ready | VULNERABLE = classical only | HYBRID = transitionary';
COMMENT ON COLUMN public.cbom_records.nist_standard IS 'Recommended NIST PQC standard for replacement';


-- ------------------------------------------------------------
-- TABLE 4: audit_logs
-- Compliance audit trail — immutable append-only log.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        REFERENCES auth.users(id) ON DELETE SET NULL,  -- NULL if system event
    action      TEXT        NOT NULL,   -- e.g., SCAN_STARTED, LOGIN, REPORT_EXPORTED
    domain      TEXT,                   -- domain related to the action (if applicable)
    ip_address  TEXT,                   -- client IP
    metadata    JSONB       DEFAULT '{}',  -- flexible key-values for extra context
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  public.audit_logs          IS 'Immutable compliance audit log — SRS Section 5.4 (FR-17, FR-18)';
COMMENT ON COLUMN public.audit_logs.metadata IS 'Structured JSON: risk_score, duration, error_message, etc.';


-- ============================================================
-- SECTION 3: INDEXES
-- ============================================================

-- scan_results
CREATE INDEX IF NOT EXISTS idx_scan_results_user_id   ON public.scan_results (user_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_domain     ON public.scan_results (domain);
CREATE INDEX IF NOT EXISTS idx_scan_results_status     ON public.scan_results (scan_status);
CREATE INDEX IF NOT EXISTS idx_scan_results_risk_level ON public.scan_results (risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_results_created_at ON public.scan_results (created_at DESC);

-- cbom_records
CREATE INDEX IF NOT EXISTS idx_cbom_scan_id    ON public.cbom_records (scan_id);
CREATE INDEX IF NOT EXISTS idx_cbom_pqc_status ON public.cbom_records (pqc_status);
CREATE INDEX IF NOT EXISTS idx_cbom_algorithm  ON public.cbom_records (algorithm);

-- audit_logs
CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON public.audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON public.audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON public.audit_logs (created_at DESC);

-- JSONB index for metadata queries (e.g., filter by risk_score in metadata)
CREATE INDEX IF NOT EXISTS idx_audit_metadata  ON public.audit_logs USING GIN (metadata);


-- ============================================================
-- SECTION 4: ROW LEVEL SECURITY (RLS)
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE public.profiles    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cbom_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs  ENABLE ROW LEVEL SECURITY;


-- ------------------------------------------------------------
-- RLS: profiles
-- Users can read and update only their own profile.
-- ------------------------------------------------------------
CREATE POLICY "profiles: user can read own"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "profiles: user can update own"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- Supabase trigger handles INSERT (handle_new_user), no direct insert needed.
-- Admins (via service_role key) bypass RLS entirely.


-- ------------------------------------------------------------
-- RLS: scan_results
-- Users can CREATE, READ, UPDATE, DELETE their own scans.
-- ------------------------------------------------------------
CREATE POLICY "scan_results: user can insert own"
    ON public.scan_results FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "scan_results: user can select own"
    ON public.scan_results FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "scan_results: user can update own"
    ON public.scan_results FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "scan_results: user can delete own"
    ON public.scan_results FOR DELETE
    USING (auth.uid() = user_id);


-- ------------------------------------------------------------
-- RLS: cbom_records
-- Users can access CBOM data for scans they own.
-- On scan deletion, CBOM records are cascade deleted.
-- ------------------------------------------------------------
CREATE POLICY "cbom_records: user can select own"
    ON public.cbom_records FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.scan_results sr
            WHERE sr.id = cbom_records.scan_id
              AND sr.user_id = auth.uid()
        )
    );

CREATE POLICY "cbom_records: user can insert own"
    ON public.cbom_records FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scan_results sr
            WHERE sr.id = cbom_records.scan_id
              AND sr.user_id = auth.uid()
        )
    );

CREATE POLICY "cbom_records: user can delete own"
    ON public.cbom_records FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM public.scan_results sr
            WHERE sr.id = cbom_records.scan_id
              AND sr.user_id = auth.uid()
        )
    );


-- ------------------------------------------------------------
-- RLS: audit_logs
-- Users can only READ their own audit entries.
-- INSERT is performed by backend using service_role key (bypasses RLS).
-- ------------------------------------------------------------
CREATE POLICY "audit_logs: user can read own"
    ON public.audit_logs FOR SELECT
    USING (auth.uid() = user_id);

-- Service role (backend) has full access by default (bypasses RLS).


-- ============================================================
-- SECTION 5: HELPER VIEWS
-- ============================================================

-- Aggregated dashboard statistics per user
CREATE OR REPLACE VIEW public.user_dashboard_stats AS
SELECT
    sr.user_id,
    COUNT(*)                                            AS total_scans,
    COUNT(*) FILTER (WHERE sr.risk_level = 'HIGH')      AS high_risk_count,
    COUNT(*) FILTER (WHERE sr.risk_level = 'MEDIUM')    AS medium_risk_count,
    COUNT(*) FILTER (WHERE sr.risk_level = 'LOW')       AS low_risk_count,
    ROUND(AVG(sr.quantum_risk_score), 1)                AS avg_risk_score,
    ROUND(AVG(sr.pqc_readiness_pct), 1)                 AS avg_pqc_readiness,
    COUNT(*) FILTER (WHERE sr.scan_status = 'failed')   AS failed_scans,
    MAX(sr.created_at)                                  AS last_scan_at
FROM public.scan_results sr
GROUP BY sr.user_id;

COMMENT ON VIEW public.user_dashboard_stats IS 'Pre-aggregated stats for the frontend dashboard cards';


-- ============================================================
-- SECTION 6: SAMPLE DATA (Reads a real auth.users UUID)
-- ============================================================
-- PREREQUISITE: You must have at least one user in Supabase Auth.
--   → Go to: Supabase Dashboard → Authentication → Users → Add User
--   → Create any user (e.g., test@pnbhackathon.in / any password)
--   → Then run this block — it will auto-pick that user's UUID.
-- ============================================================

DO $$
DECLARE
    v_user_id   UUID;
    v_scan_id   UUID := gen_random_uuid();
BEGIN

    -- ── Step 0: Get a real UUID from auth.users ─────────────────────
    -- This is REQUIRED because profiles.id is a FK to auth.users.id.
    SELECT id INTO v_user_id FROM auth.users LIMIT 1;

    IF v_user_id IS NULL THEN
        RAISE EXCEPTION
            '❌ No users found in auth.users. '
            'Please create a user first: '
            'Supabase Dashboard → Authentication → Users → Add User';
    END IF;

    RAISE NOTICE '✅ Using real auth user: %', v_user_id;

    -- ── Step 1: Update the profile for that real user ───────────────
    -- The profile row was auto-created by handle_new_user() trigger on signup.
    -- We just update the name and role here.
    UPDATE public.profiles
    SET full_name = 'Chanukya Chintada',
        role      = 'admin'
    WHERE id = v_user_id;

    -- ── Step 2: Insert a sample scan result ─────────────────────────
    INSERT INTO public.scan_results (
        id, user_id, domain, ip_address, scan_status,
        quantum_risk_score, risk_level, tls_version,
        certificate_issuer, pqc_readiness_pct, scan_duration
    ) VALUES (
        v_scan_id,
        v_user_id,
        'pnbindia.in',
        '122.177.12.34',
        'completed',
        72,
        'HIGH',
        'TLSv1.2',
        'DigiCert Inc.',
        28.50,
        4.231
    );

    RAISE NOTICE '✅ scan_results row inserted: %', v_scan_id;

    -- ── Step 3: Insert CBOM records linked to that scan ─────────────
    INSERT INTO public.cbom_records
        (scan_id, algorithm, key_length, cipher_suite, pqc_status, recommendation, nist_standard)
    VALUES
        (v_scan_id, 'RSA',   2048, 'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'VULNERABLE', 'Migrate to ML-KEM-768 (Kyber)',              'FIPS-203'),
        (v_scan_id, 'ECDSA', 256,  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'VULNERABLE', 'Migrate to ML-DSA (Dilithium)',              'FIPS-204'),
        (v_scan_id, 'AES',   256,  'TLS_AES_256_GCM_SHA384',
            'SAFE',       'AES-256 is Grover-resistant, no change needed', NULL);

    RAISE NOTICE '✅ cbom_records rows inserted (3 algorithms)';

    -- ── Step 4: Insert an audit log entry ───────────────────────────
    INSERT INTO public.audit_logs
        (user_id, action, domain, ip_address, metadata)
    VALUES (
        v_user_id,
        'SCAN_COMPLETED',
        'pnbindia.in',
        '127.0.0.1',
        jsonb_build_object(
            'risk_score',       72,
            'risk_level',       'HIGH',
            'duration_seconds', 4.231,
            'algorithms_found', jsonb_build_array('RSA', 'ECDSA', 'AES'),
            'vulnerable_count', 2,
            'scan_id',          v_scan_id::text
        )
    );

    RAISE NOTICE '✅ audit_logs row inserted';
    RAISE NOTICE '─────────────────────────────────────────';
    RAISE NOTICE 'All test data inserted successfully!';
    RAISE NOTICE '  user_id : %', v_user_id;
    RAISE NOTICE '  scan_id : %', v_scan_id;
    RAISE NOTICE '─────────────────────────────────────────';

END;
$$;


-- ============================================================
-- SECTION 7: QUICK VALIDATION QUERIES
-- ============================================================

-- Check all tables were created
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

-- Check all RLS policies
SELECT schemaname, tablename, policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;

-- Check all indexes
SELECT indexname, tablename, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename;


-- ============================================================
-- END OF SCHEMA
-- ============================================================
-- Quantum-Proof Systems Scanner | Team CypherRed261
-- PSB Hackathon 2026 | Lovely Professional University
-- ============================================================


-- === FILE: supabase_migration_assets_nameservers.sql ===
-- ============================================================
-- MIGRATION: Create missing tables — assets & nameserver_records
-- Quantum-Proof Systems Scanner | Team CypherRed261
-- PSB Hackathon 2026
-- ============================================================
-- PURPOSE : These two tables were referenced by backend/database.py
--           but never included in the original schema SQL files.
-- SAFE     : Fully idempotent. Uses CREATE TABLE IF NOT EXISTS for the
--            base structure, then ALTER TABLE ADD COLUMN IF NOT EXISTS
--            for every extended column.
--            Safe to re-run whether the table is brand-new OR already
--            exists with partial columns (fixes the ssl_fingerprint error).
-- ============================================================


-- ============================================================
-- TABLE 1: public.assets
-- PHASE A: Create base table (no-op if it already exists)
-- ============================================================

CREATE TABLE IF NOT EXISTS public.assets (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    risk_level  TEXT        NOT NULL DEFAULT 'LOW',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- PHASE B: Add extended columns (safe no-op if already present)
-- Each ALTER is independent — runs even if others are already there.
-- ============================================================

-- Core fields from add_asset() insert (database.py lines 521-530)
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS url              TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS ipv4             TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS ipv6             TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS asset_type       TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS owner_department TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS cert_status      TEXT DEFAULT 'Valid';

-- Scan tracking (get_dashboard_stats line 427; renderAssetsTable line 891)
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS scan_count    INTEGER     DEFAULT 0;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS last_scan_at  TIMESTAMPTZ;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS last_scan_by  TEXT;

-- SSL / cert discovery (renderAssetDiscovery SSL tab lines 847-852)
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS ssl_fingerprint TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS cert_valid_from TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS ca_name         TEXT;

-- Domain registry (renderAssetDiscovery Domains tab lines 829-831)
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS registration_date TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS registrar         TEXT;

-- Audit trail (add_asset line 527; update_asset line 555)
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS updated_by TEXT;


-- ============================================================
-- PHASE C: Comments (safe to run after all columns exist)
-- ============================================================

COMMENT ON TABLE  public.assets                    IS 'Registered asset inventory for PQC compliance tracking';
COMMENT ON COLUMN public.assets.user_id            IS 'Owner references auth.users.id';
COMMENT ON COLUMN public.assets.asset_type         IS 'Web App | API | Server | Gateway | Load Balancer | Other';
COMMENT ON COLUMN public.assets.risk_level         IS 'LOW | MEDIUM | HIGH | CRITICAL';
COMMENT ON COLUMN public.assets.scan_count         IS 'Total scans run against this asset';
COMMENT ON COLUMN public.assets.ssl_fingerprint    IS 'SHA fingerprint of SSL cert (discovery tab)';
COMMENT ON COLUMN public.assets.cert_valid_from    IS 'Certificate validity start date (ISO text)';
COMMENT ON COLUMN public.assets.ca_name            IS 'Certificate Authority name';
COMMENT ON COLUMN public.assets.registration_date  IS 'Domain registration date';
COMMENT ON COLUMN public.assets.registrar          IS 'Domain registrar';


-- ============================================================
-- PHASE D: Trigger, Indexes, RLS
-- ============================================================

CREATE OR REPLACE FUNCTION public.handle_assets_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_assets_updated ON public.assets;
CREATE TRIGGER on_assets_updated
    BEFORE UPDATE ON public.assets
    FOR EACH ROW EXECUTE FUNCTION public.handle_assets_updated_at();

CREATE INDEX IF NOT EXISTS idx_assets_user_id    ON public.assets (user_id);
CREATE INDEX IF NOT EXISTS idx_assets_risk_level ON public.assets (risk_level);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON public.assets (asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON public.assets (created_at DESC);

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "assets: user can select own" ON public.assets;
DROP POLICY IF EXISTS "assets: user can insert own" ON public.assets;
DROP POLICY IF EXISTS "assets: user can update own" ON public.assets;
DROP POLICY IF EXISTS "assets: user can delete own" ON public.assets;

CREATE POLICY "assets: user can select own"
    ON public.assets FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "assets: user can insert own"
    ON public.assets FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "assets: user can update own"
    ON public.assets FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "assets: user can delete own"
    ON public.assets FOR DELETE
    USING (auth.uid() = user_id);


-- ============================================================
-- TABLE 2: public.nameserver_records
-- PHASE A: Create base table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.nameserver_records (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    hostname    TEXT        NOT NULL,
    record_type TEXT        NOT NULL DEFAULT 'NS',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- PHASE B: Add extended columns
-- ============================================================

-- DNS display fields (renderNameserverTable lines 994-996)
ALTER TABLE public.nameserver_records ADD COLUMN IF NOT EXISTS ipv4     TEXT;
ALTER TABLE public.nameserver_records ADD COLUMN IF NOT EXISTS ipv6     TEXT;
ALTER TABLE public.nameserver_records ADD COLUMN IF NOT EXISTS ttl      INTEGER;

-- Resolved record value (e.g. "ns1.cloudflare.com")
ALTER TABLE public.nameserver_records ADD COLUMN IF NOT EXISTS ns_value TEXT;

-- Optional FK to the scan that discovered this record
ALTER TABLE public.nameserver_records
    ADD COLUMN IF NOT EXISTS scan_id UUID REFERENCES public.scan_results(id) ON DELETE SET NULL;


-- ============================================================
-- PHASE C: Comments
-- ============================================================

COMMENT ON TABLE  public.nameserver_records             IS 'DNS record inventory discovered during scans';
COMMENT ON COLUMN public.nameserver_records.user_id     IS 'Owner references auth.users.id';
COMMENT ON COLUMN public.nameserver_records.hostname    IS 'Domain the record belongs to (filter key)';
COMMENT ON COLUMN public.nameserver_records.record_type IS 'DNS record type: A | AAAA | NS | MX';
COMMENT ON COLUMN public.nameserver_records.ns_value    IS 'Resolved value (nameserver FQDN, IP, MX host)';
COMMENT ON COLUMN public.nameserver_records.ttl         IS 'DNS TTL in seconds';
COMMENT ON COLUMN public.nameserver_records.scan_id     IS 'FK to scan that discovered this record (nullable)';


-- ============================================================
-- PHASE D: Indexes, RLS
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_ns_user_id     ON public.nameserver_records (user_id);
CREATE INDEX IF NOT EXISTS idx_ns_hostname    ON public.nameserver_records (hostname);
CREATE INDEX IF NOT EXISTS idx_ns_record_type ON public.nameserver_records (record_type);
CREATE INDEX IF NOT EXISTS idx_ns_created_at  ON public.nameserver_records (created_at DESC);

ALTER TABLE public.nameserver_records ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "nameserver_records: user can select own" ON public.nameserver_records;
DROP POLICY IF EXISTS "nameserver_records: user can insert own" ON public.nameserver_records;
DROP POLICY IF EXISTS "nameserver_records: user can delete own" ON public.nameserver_records;

CREATE POLICY "nameserver_records: user can select own"
    ON public.nameserver_records FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "nameserver_records: user can insert own"
    ON public.nameserver_records FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "nameserver_records: user can delete own"
    ON public.nameserver_records FOR DELETE
    USING (auth.uid() = user_id);


-- ============================================================
-- VERIFICATION — confirm success after running
-- ============================================================

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('assets', 'nameserver_records')
ORDER BY table_name;

SELECT column_name, data_type, column_default, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'assets'
ORDER BY ordinal_position;

SELECT column_name, data_type, column_default, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'nameserver_records'
ORDER BY ordinal_position;

SELECT tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN ('assets', 'nameserver_records')
ORDER BY tablename, policyname;

-- ============================================================
-- END OF MIGRATION
-- Quantum-Proof Systems Scanner | Team CypherRed261
-- ============================================================


-- === FILE: supabase_migration_crypto_features.sql ===
ALTER TABLE public.scan_results
ADD COLUMN IF NOT EXISTS crypto_mode TEXT,
ADD COLUMN IF NOT EXISTS crypto_agility_score INTEGER;


-- === FILE: supabase_migration_quantum_risks.sql ===
ALTER TABLE public.scan_results
ADD COLUMN IF NOT EXISTS quantum_risk_horizon TEXT,
ADD COLUMN IF NOT EXISTS hndl_risk BOOLEAN DEFAULT FALSE;

