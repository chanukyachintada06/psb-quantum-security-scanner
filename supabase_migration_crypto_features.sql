ALTER TABLE public.scan_results
ADD COLUMN IF NOT EXISTS crypto_mode TEXT,
ADD COLUMN IF NOT EXISTS crypto_agility_score INTEGER;
