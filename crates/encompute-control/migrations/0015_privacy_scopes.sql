-- Encompute control plane, schema version 15: privacy scopes (governed
-- projects, differential-privacy scopes, part 2).
--
-- A scope is a sub-ledger of one population for one project, purpose (by
-- name, so a new revision of the purpose does not need a new allocation)
-- and, optionally, program. It is proposed by one person of the population's
-- organization and becomes active when a different person of it approves
-- (four eyes: the database also refuses an approver who is the proposer).
-- Its hash-chained entries are the ledger `scope:<id>` (see schema version
-- 14); the population's cap stays authoritative.
--
-- At most one active scope serves one (population, project, purpose,
-- program), and an active scope's fields never change.

CREATE TABLE privacy_scopes (
    id              TEXT PRIMARY KEY,
    population_id   TEXT NOT NULL REFERENCES privacy_populations(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    project_id      TEXT NOT NULL REFERENCES projects(id),
    purpose         TEXT NOT NULL,
    -- NULL: every program of the purpose.
    program_id      TEXT,
    epsilon         DOUBLE PRECISION NOT NULL CHECK (epsilon > 0),
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'active')),
    proposed_by     TEXT NOT NULL,
    approved_by     TEXT,
    ledger_key      TEXT UNIQUE REFERENCES privacy_ledgers(asset_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    CHECK ((status = 'active') = (ledger_key IS NOT NULL)),
    CHECK ((status = 'active') = (approved_by IS NOT NULL)),
    CHECK (approved_by IS NULL OR approved_by <> proposed_by),
    CHECK (ledger_key IS NULL OR ledger_key = 'scope:' || id)
);

CREATE UNIQUE INDEX privacy_scopes_one_active
    ON privacy_scopes (population_id, project_id, purpose, COALESCE(program_id, ''))
    WHERE status = 'active';

CREATE INDEX privacy_scopes_project ON privacy_scopes (project_id, status);

CREATE FUNCTION encompute_privacy_scope_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a privacy scope is never removed' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.population_id IS DISTINCT FROM OLD.population_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.program_id IS DISTINCT FROM OLD.program_id
       OR NEW.epsilon IS DISTINCT FROM OLD.epsilon
       OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by THEN
        RAISE EXCEPTION 'a privacy scope is immutable: propose another' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND (NEW.status <> 'active'
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.ledger_key IS DISTINCT FROM OLD.ledger_key) THEN
        RAISE EXCEPTION 'an active privacy scope stays as allocated' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER privacy_scopes_guard BEFORE UPDATE OR DELETE ON privacy_scopes
    FOR EACH ROW EXECUTE FUNCTION encompute_privacy_scope_guard();
