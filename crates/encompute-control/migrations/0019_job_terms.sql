-- Encompute control plane, schema version 19: job terms.
--
-- Job terms say which jobs a project runs at all: which execution specs,
-- for which purposes, submitted by which member organizations, on
-- evaluators with which receipt keys, how many in total, and in which time
-- window (they can come from an agreement between the organizations). An
-- organization admin of one member organization proposes them, and they
-- take effect when an organization admin of every member organization has
-- accepted them. While a project has active terms, the control plane
-- refuses every job outside them, schedules a job only on an evaluator
-- they name and grants it nothing beyond their end. A project that
-- requires terms runs nothing until terms are active, and once terms are
-- active it always requires them. Standard and governed projects alike;
-- jobs submitted before have no terms and are unchanged.
--
-- A project coming to require terms and terms being superseded are also
-- events of the governance log (security-negative sets): a restored
-- database that shows them undone is refused at startup.

ALTER TABLE projects
    ADD COLUMN terms_required BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE job_terms (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    -- The proposing organization.
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    -- SHA-256 of the canonical JSON of `document`.
    digest          TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document        JSONB NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'active', 'superseded')),
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at    TIMESTAMPTZ,
    -- How many jobs were submitted under them, kept by the database as each
    -- is inserted (below): never more than the document's max_jobs, never
    -- lower again.
    jobs_submitted  BIGINT NOT NULL DEFAULT 0 CHECK (jobs_submitted >= 0),
    -- Active terms were activated; proposed ones not yet. Superseded terms
    -- were either (active ones replaced, or proposals that newer terms
    -- overtook before they were accepted).
    CONSTRAINT job_terms_activation CHECK (
        (status = 'proposed' AND activated_at IS NULL)
        OR (status = 'active' AND activated_at IS NOT NULL)
        OR status = 'superseded')
);
-- At most one set of terms governs a project at a time.
CREATE UNIQUE INDEX job_terms_one_active ON job_terms (project_id) WHERE status = 'active';
CREATE INDEX job_terms_project ON job_terms (project_id, created_at);

-- One acceptance per member organization, by a person who is an
-- organization admin homed there (the proposer's organization accepts by
-- proposing).
CREATE TABLE job_terms_acceptances (
    terms_id        TEXT NOT NULL REFERENCES job_terms(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    accepted_by     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (terms_id, organization_id)
);

-- The terms a job was admitted under (every job submitted while its
-- project had active terms), and its number under them (1 for the first,
-- up to their max_jobs). Set at submission, never changed.
ALTER TABLE jobs
    ADD COLUMN terms_id TEXT REFERENCES job_terms(id),
    ADD COLUMN terms_seq BIGINT,
    ADD CONSTRAINT jobs_terms_seq CHECK ((terms_id IS NULL) = (terms_seq IS NULL));
CREATE UNIQUE INDEX jobs_terms ON jobs (terms_id, terms_seq) WHERE terms_id IS NOT NULL;

-- Terms are never edited or removed: their document, digest, project and
-- proposer are fixed, and their status only moves forward: proposed, then
-- active, then superseded; or proposed, then superseded, when other terms
-- of the project became active first. Their count of jobs only goes up, one
-- at a time, while they are active.
CREATE FUNCTION encompute_job_terms_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'job terms are never removed (%)', TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.document IS DISTINCT FROM OLD.document
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'job terms are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((NEW.status = OLD.status AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at)
            OR (OLD.status = 'proposed' AND NEW.status = 'active')
            OR (OLD.status IN ('proposed', 'active') AND NEW.status = 'superseded'
                AND NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at)) THEN
        RAISE EXCEPTION 'job terms go from proposed to active to superseded, never back'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.jobs_submitted IS DISTINCT FROM OLD.jobs_submitted
       AND NOT (NEW.jobs_submitted = OLD.jobs_submitted + 1
                AND OLD.status = 'active' AND NEW.status = 'active') THEN
        RAISE EXCEPTION 'the jobs of job terms are counted one at a time while they are active'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_terms_guard
    BEFORE UPDATE OR DELETE ON job_terms
    FOR EACH ROW EXECUTE FUNCTION encompute_job_terms_guard();
CREATE TRIGGER job_terms_no_truncate
    BEFORE TRUNCATE ON job_terms
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_job_terms_guard();

-- Acceptances are history: never changed or removed.
CREATE FUNCTION encompute_job_terms_acceptances_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'job terms acceptances are append-only (%)', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_terms_acceptances_append_only
    BEFORE UPDATE OR DELETE ON job_terms_acceptances
    FOR EACH ROW EXECUTE FUNCTION encompute_job_terms_acceptances_append_only();
CREATE TRIGGER job_terms_acceptances_no_truncate
    BEFORE TRUNCATE ON job_terms_acceptances
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_job_terms_acceptances_append_only();

-- A job inserted under terms is counted against them and numbered: only
-- under its own project's active terms, and never beyond their max_jobs
-- (the control plane checks both first, under the same row lock, and
-- audits a refusal; this holds whatever inserts the job), and a project
-- that requires terms gets no job without them. Their window is checked by
-- the control plane only.
CREATE FUNCTION encompute_job_terms_count() RETURNS trigger AS $$
DECLARE
    n BIGINT;
BEGIN
    IF NEW.terms_id IS NULL THEN
        IF NEW.terms_seq IS NOT NULL THEN
            RAISE EXCEPTION 'a job without terms has no number under them'
                USING ERRCODE = 'check_violation';
        END IF;
        -- A project that requires terms runs no job without them.
        IF EXISTS (SELECT 1 FROM projects WHERE id = NEW.project_id AND terms_required) THEN
            RAISE EXCEPTION 'project % runs jobs only under job terms', NEW.project_id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    UPDATE job_terms SET jobs_submitted = jobs_submitted + 1
     WHERE id = NEW.terms_id AND project_id = NEW.project_id AND status = 'active'
       AND jobs_submitted < (document->>'max_jobs')::bigint
    RETURNING jobs_submitted INTO n;
    IF n IS NULL THEN
        RAISE EXCEPTION 'job terms % are not active in the job''s project, or every job they allow was submitted', NEW.terms_id
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.terms_seq := n;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER jobs_terms_count BEFORE INSERT ON jobs
    FOR EACH ROW EXECUTE FUNCTION encompute_job_terms_count();

-- A job's terms are fixed at submission, and a project that requires terms
-- keeps requiring them.
CREATE FUNCTION encompute_job_terms_id_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.terms_id IS DISTINCT FROM OLD.terms_id
       OR NEW.terms_seq IS DISTINCT FROM OLD.terms_seq THEN
        RAISE EXCEPTION 'a job''s terms are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER jobs_terms_guard BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION encompute_job_terms_id_guard();

CREATE FUNCTION encompute_project_terms_required_guard() RETURNS trigger AS $$
BEGIN
    IF OLD.terms_required AND NOT NEW.terms_required THEN
        RAISE EXCEPTION 'a project that requires job terms keeps requiring them'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_terms_guard BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION encompute_project_terms_required_guard();
