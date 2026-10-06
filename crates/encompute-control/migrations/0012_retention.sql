-- Encompute control plane, schema version 12: retention (governed
-- projects, part 7), and re-issued co-signatures of derived results.
--
-- A dataset version carries its owner's retention:
--
-- - `delete_after` (schema version 7): from then on no job uses the
--   version and nothing derived from it is used, derived from or exported.
--   Fixed at registration; the owner may only bring it forward (the version
--   guard refuses pushing it back or clearing it).
-- - `retention_until`: until when the owner keeps the data. Fixed at
--   registration, and never after `delete_after`: the deletion date cannot
--   be brought forward past it.
-- - `evidence_retention_until`: until when the evidence about the version
--   (receipts, audit events, anchors, release records) is kept. It may only
--   be extended, never shortened or cleared.
--
-- Once `delete_after` passes, the control plane marks the version expired
-- (`expired_at`, final, schema version 6), marks every derived result
-- downstream `source_expired_at` (set once, never cleared), fails their jobs
-- that have not started, anchors the expiry and only then tells the key
-- broker (`asset.expired`). Deleting the data itself is the owner's
-- storage's job; Encompute blocks its use and records it.
--
-- When a lineage owner of a derived result rotates its governance key, the
-- control plane re-issues its co-signature of the custodian's release record
-- with the owners' current key IDs (the record, version and parents
-- unchanged), so the custodian's broker can re-bind the key. The co-signature
-- stored at registration stays as it was; each re-issue is recorded here,
-- append-only.
--
-- Standard projects are unchanged: the new columns are NULL for their
-- assets unless their owner sets them.

ALTER TABLE assets ADD COLUMN retention_until BIGINT;
ALTER TABLE assets ADD COLUMN evidence_retention_until BIGINT;
ALTER TABLE assets ADD COLUMN source_expired_at TIMESTAMPTZ;

ALTER TABLE assets ADD CONSTRAINT assets_retention_versioned CHECK (
    (retention_until IS NULL OR series IS NOT NULL)
    AND (evidence_retention_until IS NULL OR series IS NOT NULL)
);

-- The data is kept at least until `retention_until`, so it is never to be
-- deleted before then.
ALTER TABLE assets ADD CONSTRAINT assets_retention_before_deletion CHECK (
    retention_until IS NULL OR delete_after IS NULL OR retention_until <= delete_after
);

CREATE FUNCTION encompute_asset_retention_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.retention_until IS DISTINCT FROM OLD.retention_until THEN
        RAISE EXCEPTION 'a dataset version''s retention is fixed at registration'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.evidence_retention_until IS NOT NULL
       AND (NEW.evidence_retention_until IS NULL
            OR NEW.evidence_retention_until < OLD.evidence_retention_until) THEN
        RAISE EXCEPTION 'evidence retention is only extended, never shortened or cleared'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.source_expired_at IS NOT NULL
       AND NEW.source_expired_at IS DISTINCT FROM OLD.source_expired_at THEN
        RAISE EXCEPTION 'an asset''s source expiry is final'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER assets_retention_guard BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION encompute_asset_retention_guard();

CREATE INDEX assets_delete_after ON assets (delete_after)
    WHERE delete_after IS NOT NULL AND expired_at IS NULL;

-- The control plane's re-issued co-signatures of derived results' release
-- records (append-only): the latest is the one in force.
CREATE TABLE derived_cosignatures (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    cosignature JSONB NOT NULL,
    issued_at   BIGINT NOT NULL,
    issued_by   TEXT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, issued_at)
);

CREATE FUNCTION encompute_derived_cosignatures_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'derived co-signatures are append-only' USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER derived_cosignatures_append_only BEFORE UPDATE OR DELETE ON derived_cosignatures
    FOR EACH ROW EXECUTE FUNCTION encompute_derived_cosignatures_append_only();
