-- Encompute control plane, schema version 20: the jobs of job terms are
-- counted and numbered by the database.
--
-- Each set of job terms keeps how many jobs were submitted under it, and
-- each job its number under them (1 for the first, up to their max_jobs),
-- both kept by the database as the job is inserted: only under its own
-- project's active terms and never beyond their max_jobs, whatever inserts
-- the job. A project that requires terms gets no job without them. The
-- count never goes down; it may only rise past the jobs the database holds
-- when recovery restores the count the governance log anchored (a
-- restored backup that lost jobs admitted under terms).
--
-- A database that ran schema version 19 gets its counts and numbers from
-- the jobs it holds: each set of terms counts its jobs, numbered in the
-- order they were submitted.

ALTER TABLE job_terms
    ADD COLUMN jobs_submitted BIGINT NOT NULL DEFAULT 0 CHECK (jobs_submitted >= 0);

ALTER TABLE jobs
    ADD COLUMN terms_seq BIGINT;

-- The backfill, before the triggers below (version 19's guards let it
-- through: they know neither column).
UPDATE jobs j SET terms_seq = n.seq
  FROM (SELECT id, row_number() OVER (PARTITION BY terms_id ORDER BY created_at, id) AS seq
          FROM jobs WHERE terms_id IS NOT NULL) n
 WHERE j.id = n.id;
UPDATE job_terms x SET jobs_submitted = n.jobs
  FROM (SELECT terms_id, count(*) AS jobs FROM jobs
         WHERE terms_id IS NOT NULL GROUP BY terms_id) n
 WHERE x.id = n.terms_id;

ALTER TABLE jobs
    ADD CONSTRAINT jobs_terms_seq CHECK ((terms_id IS NULL) = (terms_seq IS NULL));
-- A job's number is unique under its terms (and pages the jobs under them).
DROP INDEX jobs_terms;
CREATE UNIQUE INDEX jobs_terms ON jobs (terms_id, terms_seq) WHERE terms_id IS NOT NULL;

-- Terms are never edited or removed: their document, digest, project and
-- proposer are fixed, and their status only moves forward: proposed, then
-- active, then superseded; or proposed, then superseded, when other terms
-- of the project became active first. Their count of jobs never goes down
-- (it goes up by one with each job inserted under them, below, and
-- recovery may raise it to the count the governance log anchored).
CREATE OR REPLACE FUNCTION encompute_job_terms_guard() RETURNS trigger AS $$
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
    IF NEW.jobs_submitted < OLD.jobs_submitted THEN
        RAISE EXCEPTION 'the count of the jobs of job terms never goes down'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.jobs_submitted > (NEW.document->>'max_jobs')::bigint THEN
        RAISE EXCEPTION 'the count of the jobs of job terms never exceeds their max_jobs'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

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

-- A job's terms and its number under them are fixed at submission.
CREATE OR REPLACE FUNCTION encompute_job_terms_id_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.terms_id IS DISTINCT FROM OLD.terms_id
       OR NEW.terms_seq IS DISTINCT FROM OLD.terms_seq THEN
        RAISE EXCEPTION 'a job''s terms are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

-- Each job admitted under terms is an event of the governance log
-- (`terms.job_admitted`: the job, its terms and its number under them),
-- anchored before the submission is acknowledged. The latest of a set of
-- terms is the count the database must still hold at startup: one index
-- probe per set of terms, newest first.
CREATE INDEX governance_events_terms_job_admitted
    ON governance_events ((body #>> '{refs,terms}'), gseq DESC)
    WHERE kind = 'terms.job_admitted';
