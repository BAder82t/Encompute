-- Encompute control plane, schema version 11: derived results and exports
-- (governed projects, part 6).
--
-- A result a governed job released becomes a first-class asset: a dataset
-- version held by its custodian (the recipient organization that
-- decrypted it, never the control-plane operator), whose parents are the
-- job's exact source versions and whose registered policy and release
-- class are never wider than theirs. Its custodian signs a release record
-- of it with its governance key, and the control plane co-signs that
-- record once it has checked it against the result's real ancestry. The
-- job, output, custodian, record and co-signature are fixed at
-- registration, like the rest of a version.
--
-- Revoking a source marks its derived descendants `source_revoked_at` (set
-- once, never cleared): no new use, derivation or export of them. It does
-- not erase anything already released, and it is not the authority: every
-- use or export walks the ancestors themselves, whose revocation the state
-- anchor holds.
--
-- An export of a derived result is a single-use export ticket for one
-- recipient, redeemed at the custodian's key broker: every one issued is
-- recorded here, append-only, one row per ticket.
--
-- Standard projects are unchanged: every new column is NULL for their
-- assets, and nothing writes the new table for them.

ALTER TABLE assets ADD COLUMN derived_from_job TEXT REFERENCES jobs(id);
ALTER TABLE assets ADD COLUMN derived_output TEXT;
ALTER TABLE assets ADD COLUMN custodian_org TEXT REFERENCES organizations(id);
ALTER TABLE assets ADD COLUMN release_record JSONB;
-- The control plane's co-signature of the record, made when it validated
-- the record against the result's real ancestry: the custodian's broker
-- binds the result's key only to a record carrying it.
ALTER TABLE assets ADD COLUMN release_cosignature JSONB;
ALTER TABLE assets ADD COLUMN source_revoked_at TIMESTAMPTZ;

-- A derived asset names its job, output, custodian and signed record, all
-- or none; it is a version, and its custodian is its organization.
ALTER TABLE assets ADD CONSTRAINT assets_derived_complete CHECK (
    (derived_from_job IS NULL) = (derived_output IS NULL)
    AND (derived_from_job IS NULL) = (custodian_org IS NULL)
    AND (derived_from_job IS NULL) = (release_record IS NULL)
    AND (derived_from_job IS NULL) = (release_cosignature IS NULL)
    AND (custodian_org IS NULL OR (custodian_org = organization_id AND series IS NOT NULL))
);

-- One derived asset per job output and custodian.
CREATE UNIQUE INDEX assets_derived_once ON assets (derived_from_job, derived_output, custodian_org)
    WHERE derived_from_job IS NOT NULL;

-- A derived asset's lineage is frozen; a source revocation is final.
CREATE FUNCTION encompute_derived_asset_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.derived_from_job IS DISTINCT FROM OLD.derived_from_job
       OR NEW.derived_output IS DISTINCT FROM OLD.derived_output
       OR NEW.custodian_org IS DISTINCT FROM OLD.custodian_org
       OR NEW.release_record IS DISTINCT FROM OLD.release_record
       OR NEW.release_cosignature IS DISTINCT FROM OLD.release_cosignature THEN
        RAISE EXCEPTION 'a derived asset''s lineage is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.source_revoked_at IS NOT NULL
       AND NEW.source_revoked_at IS DISTINCT FROM OLD.source_revoked_at THEN
        RAISE EXCEPTION 'an asset''s source revocation is final'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER assets_derived_guard BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION encompute_derived_asset_guard();

-- What a ticket asks for. Every ticket issued before this version was a
-- key release.
ALTER TABLE release_tickets ADD COLUMN kind TEXT NOT NULL DEFAULT 'key_release'
    CHECK (kind IN ('key_release', 'export'));

-- Every export ticket issued (append-only): which derived result, to which
-- recipient, in which class, and who asked. A ticket is recorded once.
CREATE TABLE exports (
    id            TEXT PRIMARY KEY,
    asset_id      TEXT NOT NULL REFERENCES assets(id),
    ticket_id     TEXT NOT NULL UNIQUE REFERENCES release_tickets(ticket_id),
    recipient     TEXT NOT NULL REFERENCES organizations(id),
    release_class TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX exports_asset ON exports (asset_id);

CREATE FUNCTION encompute_exports_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'exports are append-only' USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER exports_append_only BEFORE UPDATE OR DELETE ON exports
    FOR EACH ROW EXECUTE FUNCTION encompute_exports_append_only();
