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

-- A population: one per organization and series. Its cap (the genesis in
-- `privacy_ledgers`) is fixed at creation.
CREATE TABLE privacy_populations (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    series          TEXT NOT NULL,
    ledger_key      TEXT NOT NULL UNIQUE REFERENCES privacy_ledgers(asset_id),
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, series),
    CHECK (ledger_key = 'population:' || id)
);

CREATE FUNCTION encompute_privacy_allocation_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'a privacy population is never changed or removed: its cap is allocated once (%)', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER privacy_populations_immutable BEFORE UPDATE OR DELETE ON privacy_populations
    FOR EACH ROW EXECUTE FUNCTION encompute_privacy_allocation_immutable();
