-- Encompute control plane, schema version 18: project placement
-- constraints (governed projects, residency and operators, part 2).
--
-- A governed project may carry constraints on where its ciphertexts may be
-- handled and who may operate the machines (`PlacementConstraints`). Every
-- member holds them. Any member's security admin may tighten them and the
-- change takes effect at once; loosening them (or replacing them with
-- something that admits more) needs every member organization to propose
-- the same constraints (`project_placement_proposals`), and takes effect
-- when the last one does.
--
-- `project_placements` keeps every version, append-only: a job's binding
-- names the digest of the version it was bound under, and the scheduler,
-- the start check and the broker read that exact version together with the
-- current one, so loosening later never widens what a bound job may do.

CREATE TABLE project_placements (
    project_id    TEXT NOT NULL REFERENCES projects(id),
    version       INTEGER NOT NULL CHECK (version > 0),
    constraints   JSONB NOT NULL,
    digest        TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    -- How this version relates to the one before it.
    kind          TEXT NOT NULL CHECK (kind IN ('tighten', 'loosen')),
    set_by        TEXT NOT NULL,
    set_by_org    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, version)
);
CREATE INDEX project_placements_digest ON project_placements (project_id, digest);

-- Organizations that proposed a change that is not a tightening, for the
-- version it was based on. Cleared when a new version is recorded.
CREATE TABLE project_placement_proposals (
    project_id    TEXT NOT NULL REFERENCES projects(id),
    based_on      INTEGER NOT NULL CHECK (based_on >= 0),
    digest        TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    constraints   JSONB NOT NULL,
    organization  TEXT NOT NULL,
    proposed_by   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, based_on, digest, organization)
);

-- Versions are history: never changed or removed.
CREATE FUNCTION encompute_project_placements_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'project placement versions are append-only (%)', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER project_placements_append_only
    BEFORE UPDATE OR DELETE ON project_placements
    FOR EACH ROW EXECUTE FUNCTION encompute_project_placements_append_only();
CREATE TRIGGER project_placements_no_truncate
    BEFORE TRUNCATE ON project_placements
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_project_placements_append_only();
