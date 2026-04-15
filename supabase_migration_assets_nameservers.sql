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
