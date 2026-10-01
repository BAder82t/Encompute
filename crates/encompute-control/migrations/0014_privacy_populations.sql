-- Encompute control plane, schema version 14: privacy populations
-- (governed projects, differential-privacy scopes, part 1).
--
-- A population is the authoritative differential-privacy ledger of one
-- organization's series of datasets, at one privacy unit: every release
-- from any version of the series, in any project, is charged to it, and
-- its cap is never raised. It keeps its hash-chained entries in
-- `privacy_ledgers` / `privacy_entries` like an asset's ledger, under the
-- key `population:<id>`, so that its checkpoints in the governance log, the
-- rollback checks at start, the freeze after a detected rollback and the
-- recovery all treat it exactly as they treat an asset's ledger. (Scopes,
-- the next schema version, are `scope:<id>`.)
--
-- Standard projects and assets without a population are unchanged: an
-- asset's ledger is still created with the asset and still names an
-- existing asset (the trigger below keeps what the foreign key said).

ALTER TABLE privacy_ledgers DROP CONSTRAINT privacy_ledgers_asset_id_fkey;

CREATE FUNCTION encompute_privacy_ledger_subject() RETURNS trigger AS $$
BEGIN
    IF NEW.asset_id LIKE 'population:%' OR NEW.asset_id LIKE 'scope:%' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM assets WHERE id = NEW.asset_id) THEN
        RAISE EXCEPTION 'privacy ledger % is for no asset', NEW.asset_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER privacy_ledgers_subject BEFORE INSERT ON privacy_ledgers
    FOR EACH ROW EXECUTE FUNCTION encompute_privacy_ledger_subject();

-- A population: proposed by one person of the owning organization and
-- approved by a different one (four eyes; the database also refuses an
-- approver who is the proposer), whose ledger is created at approval. At
-- most one is active per organization and series: a later population may
-- supersede it for NEW scopes (the old one keeps its history and its
-- spending, and its scopes stay readable but serve no new job). Its cap (the
-- genesis in `privacy_ledgers`) is fixed at creation.
CREATE TABLE privacy_populations (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    series          TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'active')),
    -- The proposal's cap (the genesis is written at approval).
    unit            TEXT NOT NULL,
    epsilon         DOUBLE PRECISION NOT NULL CHECK (epsilon > 0),
    delta           DOUBLE PRECISION NOT NULL CHECK (delta > 0 AND delta < 1),
    supersedes      TEXT REFERENCES privacy_populations(id),
    superseded_by   TEXT REFERENCES privacy_populations(id),
    ledger_key      TEXT UNIQUE REFERENCES privacy_ledgers(asset_id),
    proposed_by     TEXT NOT NULL,
    approved_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    CHECK ((status = 'active') = (ledger_key IS NOT NULL)),
    CHECK ((status = 'active') = (approved_by IS NOT NULL)),
    CHECK (approved_by IS NULL OR approved_by <> proposed_by),
    CHECK (ledger_key IS NULL OR ledger_key = 'population:' || id)
);

CREATE UNIQUE INDEX privacy_populations_one_active
    ON privacy_populations (organization_id, series)
    WHERE status = 'active' AND superseded_by IS NULL;

CREATE FUNCTION encompute_privacy_population_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a privacy population is never removed' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.series IS DISTINCT FROM OLD.series
       OR NEW.unit IS DISTINCT FROM OLD.unit
       OR NEW.epsilon IS DISTINCT FROM OLD.epsilon
       OR NEW.delta IS DISTINCT FROM OLD.delta
       OR NEW.supersedes IS DISTINCT FROM OLD.supersedes
       OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by THEN
        RAISE EXCEPTION 'a privacy population is immutable: its cap is allocated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND (NEW.status <> 'active'
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.ledger_key IS DISTINCT FROM OLD.ledger_key
       OR (OLD.superseded_by IS NOT NULL AND NEW.superseded_by IS DISTINCT FROM OLD.superseded_by)) THEN
        RAISE EXCEPTION 'an active privacy population stays as allocated' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER privacy_populations_guard BEFORE UPDATE OR DELETE ON privacy_populations
    FOR EACH ROW EXECUTE FUNCTION encompute_privacy_population_guard();
