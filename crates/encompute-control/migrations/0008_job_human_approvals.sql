-- Encompute control plane, schema version 8: per-job four-eyes approval
-- in governed projects (governed projects, part 3).
--
-- When an authorization a governed job runs under asks for per-job
-- four-eyes approval, the job waits until enough distinct people of that
-- authorization's owner approve it, under the owner's approval rule for
-- the project. Each row is one person's approval of one job: never the
-- job's submitter, never a service account, an auditor or someone homed
-- in another organization. The statement digest binds the job, its
-- governed execution spec and its authorization set, so an approval never
-- carries over to another spec or set.
--
-- An approval counts only while its approver still may approve: an
-- active user, homed in the organization, holding the recorded role and
-- not an auditor there. A row that stops counting stays as evidence.
--
-- Standard projects are unchanged: their job approvals stay in
-- job_approvals.

CREATE TABLE job_human_approvals (
    job_id           TEXT NOT NULL REFERENCES jobs(id),
    -- The approving (source-owning) organization, the approver's home.
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    approver_id      TEXT NOT NULL REFERENCES users(id),
    -- The role of the approval rule the approval counts for.
    role             TEXT NOT NULL,
    -- SHA256("encompute.job-approval.v1" || 0x00 || canonical {job,
    -- spec_id, authorization_set_id}), hex.
    statement_digest TEXT NOT NULL CHECK (statement_digest ~ '^[0-9a-f]{64}$'),
    at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One person approves a job once.
    PRIMARY KEY (job_id, approver_id)
);

CREATE INDEX job_human_approvals_organization ON job_human_approvals (job_id, organization_id);

CREATE FUNCTION encompute_job_human_approvals_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'a job''s approvals are append-only' USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_human_approvals_append_only BEFORE UPDATE OR DELETE ON job_human_approvals
    FOR EACH ROW EXECUTE FUNCTION encompute_job_human_approvals_append_only();

-- An approval rule names only roles a person may approve with: never
-- `auditor` (auditors never approve, so such a rule could never be met),
-- and no unknown role.
CREATE FUNCTION encompute_approval_rule_roles() RETURNS trigger AS $$
DECLARE
    r TEXT;
BEGIN
    IF jsonb_typeof(NEW.required_roles) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'an approval rule names its roles as {role: count}'
            USING ERRCODE = 'check_violation';
    END IF;
    FOR r IN SELECT jsonb_object_keys(NEW.required_roles) LOOP
        IF r = 'auditor' THEN
            RAISE EXCEPTION 'an approval rule never requires auditor: auditors never approve, so the rule could never be met'
                USING ERRCODE = 'check_violation';
        END IF;
        IF r NOT IN ('organization_admin', 'security_admin', 'data_owner', 'model_owner',
                     'ml_developer', 'operator') THEN
            RAISE EXCEPTION 'an approval rule names an unknown role %', r
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER approval_rules_roles BEFORE INSERT OR UPDATE ON approval_rules
    FOR EACH ROW EXECUTE FUNCTION encompute_approval_rule_roles();
