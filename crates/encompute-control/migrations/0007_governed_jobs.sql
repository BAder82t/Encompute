-- Encompute control plane, schema version 7: jobs in governed projects
-- (governed projects, part 3).
--
-- A job in a governed project runs for one active purpose, under an
-- owner-signed authorization for every source (the submitter's own
-- included). Submission records the purpose, the governance binding the
-- job's execution spec carries and the authorizations it runs under;
-- scheduling, start and completion check them again, strictly, on the
-- control plane's clock. A job that started inside its window may
-- complete after it, so the start time is recorded.
--
-- Standard projects are unchanged: every new column is NULL for their
-- jobs and assets, and the new triggers act only on governed rows.

-- The purpose a governed job runs for, and what it is bound to: the
-- governance binding (inputs, outputs, brokers), its GovernanceId and the
-- authorization set. Both or neither; set at submission, never changed.
ALTER TABLE jobs ADD COLUMN purpose_id TEXT REFERENCES purposes(id);
ALTER TABLE jobs ADD COLUMN governance JSONB;
ALTER TABLE jobs ADD CONSTRAINT jobs_governance_complete
    CHECK ((purpose_id IS NULL) = (governance IS NULL));
-- When the scheduled evaluator started the job (governed jobs): set once.
ALTER TABLE jobs ADD COLUMN started_at TIMESTAMPTZ;

CREATE FUNCTION encompute_job_governance_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.purpose_id IS DISTINCT FROM OLD.purpose_id
       OR NEW.governance IS DISTINCT FROM OLD.governance THEN
        RAISE EXCEPTION 'a job''s purpose and governance binding are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.governance IS NOT NULL AND (NEW.spec_id IS DISTINCT FROM OLD.spec_id
       OR NEW.program_id IS DISTINCT FROM OLD.program_id
       OR NEW.plan_id IS DISTINCT FROM OLD.plan_id
       OR NEW.source_assets IS DISTINCT FROM OLD.source_assets) THEN
        RAISE EXCEPTION 'a governed job''s execution is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'a job''s start time is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER jobs_governance_guard BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION encompute_job_governance_guard();

-- The authorizations a governed job runs under, one per source (append-only):
-- revoking one fails the job if it has not started.
CREATE TABLE job_authorizations (
    job_id            TEXT NOT NULL REFERENCES jobs(id),
    authorization_row TEXT NOT NULL REFERENCES authorizations(id),
    -- The signed document's AuthorizationId.
    authorization_id  TEXT NOT NULL,
    asset_id          TEXT NOT NULL REFERENCES assets(id),
    PRIMARY KEY (job_id, authorization_row)
);

CREATE INDEX job_authorizations_authorization ON job_authorizations (authorization_row);

CREATE FUNCTION encompute_job_authorizations_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'a job''s authorizations are append-only' USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_authorizations_append_only BEFORE UPDATE OR DELETE ON job_authorizations
    FOR EACH ROW EXECUTE FUNCTION encompute_job_authorizations_append_only();

-- When a dataset version must be deleted (its owner's retention): no job
-- uses it from then on, and a grant never outlives it. Unix seconds, set
-- at registration, versions only. The owner may bring it forward, never
-- push it back or clear it.
ALTER TABLE assets ADD COLUMN delete_after BIGINT;
ALTER TABLE assets ADD CONSTRAINT assets_delete_after_versioned
    CHECK (delete_after IS NULL OR series IS NOT NULL);

-- The version guard of schema version 5, and the deletion date only ever
-- brought forward.
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
       OR NEW.policy IS DISTINCT FROM OLD.policy THEN
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
