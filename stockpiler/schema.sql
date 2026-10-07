CREATE TABLE IF NOT EXISTS stockpile_candidates (
    candidate_id bigserial PRIMARY KEY,
    vulnerability_ids text[] NOT NULL,
    source_url text NOT NULL,
    source_commit text NOT NULL,
    discovered_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    conversion_status text NOT NULL DEFAULT 'pending'
        CHECK (conversion_status IN ('pending', 'converting', 'validated', 'rejected')),
    conversion_claimed_at timestamptz,
    conversion_error text,
    UNIQUE (source_url, source_commit)
);

ALTER TABLE stockpile_candidates
    ADD COLUMN IF NOT EXISTS conversion_claimed_at timestamptz;

CREATE TABLE IF NOT EXISTS stockpile_pocs (
    poc_id text PRIMARY KEY,
    vulnerability_ids text[] NOT NULL,
    source_url text NOT NULL,
    source_commit text NOT NULL,
    target_constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
    runtime text NOT NULL CHECK (runtime = 'python3'),
    content bytea NOT NULL,
    sha256 char(64) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    conversion_status text NOT NULL CHECK (conversion_status IN ('validated', 'rejected')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS stockpile_pocs_vulnerability_ids_idx
    ON stockpile_pocs USING gin (vulnerability_ids);
