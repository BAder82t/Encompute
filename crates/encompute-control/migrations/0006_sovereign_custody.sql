-- Encompute control plane, schema version 6: sovereign key custody,
-- per-organization key brokers and release tickets (governed projects,
-- part 2).
--
-- In a governed project an owner's key broker is the final release
-- authority: it releases a key only with the owner's signed authorization
-- and a short-lived, single-use release ticket from the control plane. In
-- sovereign custody (always, for governed projects) every source's key
-- is held by a broker its own organization registered, never a platform
-- broker.
--
-- Standard projects are unchanged: their custody is `standard`, and none of
-- the new tables holds anything for them.

-- A project's custody follows its mode and never changes: a governed
-- project is always in sovereign custody, a standard one in standard
-- custody. Omitted on insert, it is filled in from the mode.
ALTER TABLE projects ADD COLUMN custody TEXT
    CHECK (custody IN ('standard', 'sovereign'));
UPDATE projects SET custody = CASE governance WHEN 'governed' THEN 'sovereign' ELSE 'standard' END;
ALTER TABLE projects ALTER COLUMN custody SET NOT NULL;
ALTER TABLE projects ADD CONSTRAINT projects_custody_governed
    CHECK ((governance = 'governed') = (custody = 'sovereign'));

CREATE FUNCTION encompute_project_custody_default() RETURNS trigger AS $$
BEGIN
    IF NEW.custody IS NULL THEN
        NEW.custody := CASE NEW.governance WHEN 'governed' THEN 'sovereign' ELSE 'standard' END;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_custody_default BEFORE INSERT ON projects
    FOR EACH ROW EXECUTE FUNCTION encompute_project_custody_default();

CREATE FUNCTION encompute_project_custody_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.custody IS DISTINCT FROM OLD.custody THEN
        RAISE EXCEPTION 'a project''s key custody is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_custody_immutable BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION encompute_project_custody_immutable();

-- An organization's own key brokers: a key-broker service account of that
-- organization, with the public key it signs key grants with, the kind of
-- KMS behind it, the key namespace it serves and where it says it runs
-- (self-declared, never evidence). Registered by a security admin of the
-- organization. A broker's identity, organization and grant key never
-- change; it is disabled, never deleted.
CREATE TABLE key_brokers (
    id                TEXT PRIMARY KEY REFERENCES service_accounts(id),
    organization_id   TEXT NOT NULL REFERENCES organizations(id),
    grant_public_key  TEXT NOT NULL UNIQUE,
    provider_kind     TEXT NOT NULL,
    key_ref_namespace TEXT NOT NULL,
    location          JSONB NOT NULL DEFAULT '{}',
    status            TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX key_brokers_organization ON key_brokers (organization_id);

CREATE FUNCTION encompute_key_broker_guard() RETURNS trigger AS $$
DECLARE
    k TEXT;
    o TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a registered key broker is disabled, never deleted'
            USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.grant_public_key IS DISTINCT FROM OLD.grant_public_key
           OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
            RAISE EXCEPTION 'a registered key broker''s identity is immutable'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- Only a key-broker service account of the same organization: never a
    -- platform broker, never another organization's.
    SELECT kind, organization_id INTO k, o FROM service_accounts WHERE id = NEW.id;
    IF k IS DISTINCT FROM 'keybroker' OR o IS DISTINCT FROM NEW.organization_id THEN
        RAISE EXCEPTION 'an organization registers only its own key-broker service accounts'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER key_brokers_guard BEFORE INSERT OR UPDATE OR DELETE ON key_brokers
    FOR EACH ROW EXECUTE FUNCTION encompute_key_broker_guard();

-- Every release ticket issued, as signed (append-only): the evidence of
-- which workload was allowed to ask which broker for which source version,
-- and until when.
CREATE TABLE release_tickets (
    ticket_id        TEXT PRIMARY KEY,
    job_id           TEXT NOT NULL REFERENCES jobs(id),
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    broker_id        TEXT NOT NULL REFERENCES service_accounts(id),
    asset_version_id TEXT NOT NULL,
    -- The evaluator service the ticket was issued to.
    issued_to        TEXT NOT NULL,
    not_after        BIGINT NOT NULL,
    body             JSONB NOT NULL,
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX release_tickets_job ON release_tickets (job_id);

CREATE FUNCTION encompute_release_ticket_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'release tickets are append-only' USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER release_tickets_append_only BEFORE UPDATE OR DELETE ON release_tickets
    FOR EACH ROW EXECUTE FUNCTION encompute_release_ticket_append_only();

-- When an asset expired (its owner's retention ended): from then on its key
-- is never released again. Set once, never changed or cleared; anchored like
-- a revocation. (Retention itself arrives in a later phase.)
ALTER TABLE assets ADD COLUMN expired_at TIMESTAMPTZ;

CREATE FUNCTION encompute_asset_expiry_guard() RETURNS trigger AS $$
BEGIN
    IF OLD.expired_at IS NOT NULL AND NEW.expired_at IS DISTINCT FROM OLD.expired_at THEN
        RAISE EXCEPTION 'an asset''s expiry is final' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER assets_expiry_guard BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION encompute_asset_expiry_guard();

-- Governance rows are revoked, retired, disabled or superseded, never
-- deleted: nothing in the control plane deletes one, and a deleted row
-- would take its revocation (or its evidence) with it.
CREATE FUNCTION encompute_governance_never_deleted() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% rows are never deleted', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorizations_no_delete BEFORE DELETE ON authorizations
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER authorization_approvals_no_delete BEFORE DELETE ON authorization_approvals
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER authorization_recipients_no_delete BEFORE DELETE ON authorization_recipients
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER governance_keys_no_delete BEFORE DELETE ON governance_keys
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER purposes_no_delete BEFORE DELETE ON purposes
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER purpose_acceptances_no_delete BEFORE DELETE ON purpose_acceptances
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
CREATE TRIGGER approval_rules_no_delete BEFORE DELETE ON approval_rules
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_never_deleted();
