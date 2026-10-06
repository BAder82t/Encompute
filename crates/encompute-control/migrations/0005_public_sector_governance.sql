-- Encompute control plane, schema version 5: governed projects (public-sector
-- confidential data collaboration), part 1.
--
-- A governed project computes across organizations for declared purposes,
-- under owner-signed authorizations. The control plane coordinates and
-- enforces; it is not the authority: each organization's consent is a
-- signature by its own governance key, which never leaves the
-- organization's KMS or HSM. Only the public key, its fingerprint and its
-- state are stored here.
--
-- Standard projects are unchanged: every new column has a default or is
-- NULL for them, and the new triggers act only on governed or versioned
-- rows (except the governance mode itself, which nobody may change).
--
-- Later phases add release tickets, the governance event log, privacy
-- scopes, placement and linkage; nothing here anticipates their tables.

-- A project's mode is chosen at creation and never changes.
ALTER TABLE projects ADD COLUMN governance TEXT NOT NULL DEFAULT 'standard'
    CHECK (governance IN ('standard', 'governed'));

CREATE FUNCTION encompute_project_governance_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.governance IS DISTINCT FROM OLD.governance THEN
        RAISE EXCEPTION 'a project''s governance mode is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_governance_immutable BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION encompute_project_governance_immutable();

-- Governance keys: an organization's Ed25519 public key, proposed by one
-- person and approved by a different security admin. At most one is
-- active per organization. A revoked key never comes back, and its
-- revocation time, set with the revocation, never changes: from that time
-- on nothing it signed is used, while uses before it stay valid history.
CREATE TABLE governance_keys (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    -- The fingerprint of the public key.
    key_id          TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL UNIQUE,
    -- Where the private key lives (a KMS or HSM reference): never key
    -- material.
    kms_key_ref     TEXT,
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'active', 'revoked')),
    proposed_by     TEXT NOT NULL,
    approved_by     TEXT,
    revoked_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX governance_keys_one_active ON governance_keys (organization_id)
    WHERE status = 'active';

CREATE FUNCTION encompute_governance_key_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.key_id IS DISTINCT FROM OLD.key_id
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by THEN
        RAISE EXCEPTION 'a governance key is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
        RAISE EXCEPTION 'a governance key''s revocation time is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'a revoked governance key stays revoked' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'proposed' THEN
        RAISE EXCEPTION 'an active governance key is not proposed again' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER governance_keys_guard BEFORE UPDATE ON governance_keys
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_key_guard();

-- Purposes: content-addressed (the ID is the PurposeId), proposed by a
-- security admin of a member organization, approved by a different one,
-- and accepted by each organization with its governance key. Editing a
-- purpose is a new revision with a new ID; a retired purpose stays
-- retired.
CREATE TABLE purposes (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    revision        INTEGER NOT NULL CHECK (revision > 0),
    document        JSONB NOT NULL,
    valid_from      BIGINT NOT NULL,
    valid_until     BIGINT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'active', 'retired')),
    proposed_by     TEXT NOT NULL,
    approved_by     TEXT,
    retired_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ,
    UNIQUE (project_id, name, revision),
    CHECK (valid_from < valid_until),
    CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);

CREATE FUNCTION encompute_purpose_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.document IS DISTINCT FROM OLD.document
       OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
       OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
       OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by THEN
        RAISE EXCEPTION 'a purpose is immutable: propose a new revision' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
        RAISE EXCEPTION 'a purpose''s retirement time is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
        RAISE EXCEPTION 'a retired purpose stays retired' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'proposed' THEN
        RAISE EXCEPTION 'an active purpose is not proposed again' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER purposes_guard BEFORE UPDATE ON purposes
    FOR EACH ROW EXECUTE FUNCTION encompute_purpose_guard();

-- An organization's signed acceptance of a purpose.
CREATE TABLE purpose_acceptances (
    purpose_id        TEXT NOT NULL REFERENCES purposes(id),
    organization_id   TEXT NOT NULL REFERENCES organizations(id),
    governance_key_id TEXT NOT NULL,
    -- The signed acceptance (body, public key, signature).
    acceptance        JSONB NOT NULL,
    accepted_by       TEXT NOT NULL,
    accepted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (purpose_id, organization_id)
);

-- How many distinct people of an organization approve its standing
-- authorizations in a project, and in which roles. Without a row the
-- default applies: two people, one data owner and one security admin.
CREATE TABLE approval_rules (
    project_id          TEXT NOT NULL REFERENCES projects(id),
    organization_id     TEXT NOT NULL REFERENCES organizations(id),
    min_distinct_humans INTEGER NOT NULL DEFAULT 2 CHECK (min_distinct_humans >= 2),
    required_roles      JSONB NOT NULL DEFAULT '{"data_owner": 1, "security_admin": 1}',
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, organization_id)
);

-- Owner authorizations (v2): proposed by a person of the owning
-- organization, approved by distinct people (four eyes), and active only
-- once the owner's governance-key signature over the approved body
-- verifies. `body` is the proposal (no approvals); the approvals are rows
-- below; `signed` is the signed document. Once approved (its quorum met)
-- an authorization is immutable evidence: its approvals and recipients
-- never change and it is not proposed again; any change of meaning is a
-- new authorization. Revocation is final, a state transition of its own,
-- and its time never changes: it blocks use from then on, never before.
CREATE TABLE authorizations (
    id                TEXT PRIMARY KEY,
    organization_id   TEXT NOT NULL REFERENCES organizations(id),
    project_id        TEXT NOT NULL REFERENCES projects(id),
    purpose_id        TEXT NOT NULL REFERENCES purposes(id),
    asset_id          TEXT NOT NULL REFERENCES assets(id),
    asset_version_id  TEXT NOT NULL,
    body              JSONB NOT NULL,
    valid_from        BIGINT NOT NULL,
    valid_until       BIGINT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'active', 'revoked')),
    -- Set on activation.
    authorization_id  TEXT UNIQUE,
    signed            JSONB,
    governance_key_id TEXT,
    proposed_by       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at      TIMESTAMPTZ,
    revoked_by        TEXT,
    revoked_at        TIMESTAMPTZ,
    -- An owner-signed revocation, when one was supplied.
    revocation        JSONB,
    CHECK (valid_from < valid_until),
    CHECK ((status = 'active') <= (signed IS NOT NULL)),
    CHECK ((signed IS NOT NULL) = (activated_at IS NOT NULL)),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX authorizations_project ON authorizations (project_id, status);

CREATE FUNCTION encompute_authorization_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.purpose_id IS DISTINCT FROM OLD.purpose_id
       OR NEW.asset_id IS DISTINCT FROM OLD.asset_id
       OR NEW.asset_version_id IS DISTINCT FROM OLD.asset_version_id
       OR NEW.body IS DISTINCT FROM OLD.body
       OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
       OR NEW.valid_until IS DISTINCT FROM OLD.valid_until THEN
        RAISE EXCEPTION 'an authorization is immutable: revoke and reissue' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.signed IS NOT NULL AND (NEW.signed IS DISTINCT FROM OLD.signed
       OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
       OR NEW.governance_key_id IS DISTINCT FROM OLD.governance_key_id
       OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a signed authorization is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
       OR NEW.revocation IS DISTINCT FROM OLD.revocation) THEN
        RAISE EXCEPTION 'an authorization''s revocation time is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'a revoked authorization stays revoked' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'approved' AND NEW.status = 'proposed' THEN
        RAISE EXCEPTION 'an approved authorization is not proposed again' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND NEW.status NOT IN ('active', 'revoked') THEN
        RAISE EXCEPTION 'an active authorization is only revoked' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorizations_guard BEFORE UPDATE ON authorizations
    FOR EACH ROW EXECUTE FUNCTION encompute_authorization_guard();

CREATE TABLE authorization_recipients (
    authorization_row TEXT NOT NULL REFERENCES authorizations(id),
    organization_id   TEXT NOT NULL,
    PRIMARY KEY (authorization_row, organization_id)
);

-- One row per person: the same person twice is one approver.
CREATE TABLE authorization_approvals (
    authorization_row TEXT NOT NULL REFERENCES authorizations(id),
    approver_id       TEXT NOT NULL,
    idp_issuer        TEXT NOT NULL,
    approver_subject  TEXT NOT NULL,
    role              TEXT NOT NULL,
    statement_digest  TEXT NOT NULL,
    -- The approval as it enters the signed document.
    evidence          JSONB NOT NULL,
    approved_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (authorization_row, approver_id),
    UNIQUE (authorization_row, idp_issuer, approver_subject)
);

-- An authorization's approvals and recipients are evidence: a row never
-- changes, and rows are added or removed only while it is proposed. Once
-- approved, active or revoked, a change of meaning is a new authorization.
CREATE FUNCTION encompute_authorization_evidence_guard() RETURNS trigger AS $$
DECLARE
    s TEXT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'an authorization''s approvals and recipients are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT status INTO s FROM authorizations
     WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.authorization_row ELSE NEW.authorization_row END
       FOR SHARE;
    IF s IS DISTINCT FROM 'proposed' THEN
        RAISE EXCEPTION 'the approvals and recipients of an authorization that is % are immutable: propose a new authorization', s
            USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER authorization_approvals_guard BEFORE INSERT OR UPDATE OR DELETE ON authorization_approvals
    FOR EACH ROW EXECUTE FUNCTION encompute_authorization_evidence_guard();
CREATE TRIGGER authorization_recipients_guard BEFORE INSERT OR UPDATE OR DELETE ON authorization_recipients
    FOR EACH ROW EXECUTE FUNCTION encompute_authorization_evidence_guard();

-- Dataset versions: each version is its own asset row, `series@version`,
-- with a content-addressed version ID. A versioned asset's identity,
-- digest, lineage and policy never change, it is never deleted, and a
-- revoked version stays revoked.
ALTER TABLE assets ADD COLUMN series TEXT;
ALTER TABLE assets ADD COLUMN version TEXT;
ALTER TABLE assets ADD COLUMN version_id TEXT UNIQUE;
ALTER TABLE assets ADD CONSTRAINT assets_version_complete
    CHECK ((series IS NULL AND version IS NULL AND version_id IS NULL)
        OR (series IS NOT NULL AND version IS NOT NULL AND version_id IS NOT NULL));
CREATE UNIQUE INDEX assets_series_version ON assets (organization_id, series, version)
    WHERE series IS NOT NULL;

CREATE FUNCTION encompute_asset_version_guard() RETURNS trigger AS $$
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
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'a revoked dataset version stays revoked' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER assets_version_guard BEFORE UPDATE OR DELETE ON assets
    FOR EACH ROW EXECUTE FUNCTION encompute_asset_version_guard();
