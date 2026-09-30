-- Encompute control plane, schema version 10: release classes and the
-- registered policy of dataset versions (governed projects, part 5).
--
-- A dataset version may carry the policy its owner registered, typed: the
-- confidentiality policy (`ir_policy`, the IR asset policy: owners,
-- readers, purposes, release, release forms, derivations, privacy) and a
-- release-class ceiling (`release_class`). A governed job's program must
-- declare a policy at least as strict for that source, and every output's
-- release class must be within the ceiling. Both are fixed at
-- registration, like the rest of a version.
--
-- Existing assets have neither (NULL): nothing changes for them.

ALTER TABLE assets ADD COLUMN ir_policy JSONB;
ALTER TABLE assets ADD COLUMN release_class TEXT
    CHECK (release_class IS NULL OR release_class IN ('never', 'boolean-only', 'aggregate-only',
        'dp-aggregate-only', 'authorized-agency-only', 'derived-artifact-only'));
ALTER TABLE assets ADD CONSTRAINT assets_registered_policy_versioned
    CHECK ((ir_policy IS NULL AND release_class IS NULL) OR series IS NOT NULL);

-- The version guard of schema version 7, with the registered policy and
-- release class frozen too.
CREATE OR REPLACE FUNCTION encompute_asset_version_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.series IS NOT NULL THEN
            RAISE EXCEPTION 'a dataset version is never deleted' USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.series IS NULL AND NEW.series IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.series IS DISTINCT FROM OLD.series
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.version_id IS DISTINCT FROM OLD.version_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.parents IS DISTINCT FROM OLD.parents
       OR NEW.lineage_root IS DISTINCT FROM OLD.lineage_root
       OR NEW.policy IS DISTINCT FROM OLD.policy
       OR NEW.ir_policy IS DISTINCT FROM OLD.ir_policy
       OR NEW.release_class IS DISTINCT FROM OLD.release_class THEN
        RAISE EXCEPTION 'a dataset version is immutable: register a new version'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.delete_after IS NOT NULL
       AND (NEW.delete_after IS NULL OR NEW.delete_after > OLD.delete_after) THEN
        RAISE EXCEPTION 'a dataset version''s deletion date is only brought forward, never extended or cleared'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'a revoked dataset version stays revoked' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
