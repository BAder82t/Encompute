-- Encompute control plane, schema version 17: evaluator locations and
-- operators (governed projects, residency and operators, part 1).
--
-- An evaluator's operator is the organization of the service account that
-- registered it (`service_accounts.organization_id`; NULL is the platform).
-- Operator-owned evaluators are service accounts of kind `evaluator` held by
-- an organization. They are scheduled only for governed jobs whose plan and
-- constraints admit them; the platform's scheduler never places a standard
-- job on one.
--
-- An evaluator's location is where it says it runs, with the evidence level
-- the claim rests on:
--
-- - `self_declared`: what the evaluator reported when it registered. Never
--   satisfies a production deployment.
-- - `operator_declared`: a person who is a security admin of the operator
--   organization declared it (`evaluator_location_declarations`, one row
--   per declaration, append-only), valid until `location_valid_until`.
-- - `attested`: taken from a verified attestation, valid until
--   `location_valid_until` (its maximum evidence age).
--
-- Evidence that is past `location_valid_until` is not evidence: the
-- control plane counts such an evaluator as self-declared. An evaluator
-- that re-registers with another location loses its evidence (back to
-- self-declared), so a declaration never vouches for a machine that moved.

ALTER TABLE evaluators
    ADD COLUMN location                JSONB,
    ADD COLUMN location_evidence       TEXT NOT NULL DEFAULT 'self_declared'
        CHECK (location_evidence IN ('self_declared', 'operator_declared', 'attested')),
    ADD COLUMN location_evidence_digest TEXT,
    ADD COLUMN location_valid_until    TIMESTAMPTZ,
    ADD COLUMN location_updated_at     TIMESTAMPTZ,
    -- Evidence beyond a self-declaration names the location it is for and
    -- how long it holds.
    ADD CONSTRAINT evaluators_location_evidence CHECK (
        location_evidence = 'self_declared'
        OR (location IS NOT NULL AND location_evidence_digest IS NOT NULL
            AND location_valid_until IS NOT NULL));

CREATE TABLE evaluator_location_declarations (
    id              TEXT PRIMARY KEY,
    evaluator_id    TEXT NOT NULL REFERENCES evaluators(id),
    -- The operator organization (`platform` for the platform's own).
    operator        TEXT NOT NULL,
    location        JSONB NOT NULL,
    evidence_digest TEXT NOT NULL,
    -- The person who declared it.
    declared_by     TEXT NOT NULL,
    declared_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ NOT NULL
);
CREATE INDEX evaluator_location_declarations_evaluator
    ON evaluator_location_declarations (evaluator_id, declared_at);

-- Declarations are history: never changed or removed.
CREATE FUNCTION encompute_location_declarations_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'location declarations are append-only (%)', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER evaluator_location_declarations_append_only
    BEFORE UPDATE OR DELETE ON evaluator_location_declarations
    FOR EACH ROW EXECUTE FUNCTION encompute_location_declarations_append_only();
CREATE TRIGGER evaluator_location_declarations_no_truncate
    BEFORE TRUNCATE ON evaluator_location_declarations
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_location_declarations_append_only();
