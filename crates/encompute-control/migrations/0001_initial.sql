-- Encompute control plane, schema version 1.
-- No plaintext assets, keys, gradients or model weights are ever stored here:
-- only identities, metadata, digests, wrapped-key references and evidence.

CREATE TABLE organizations (
    id               TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
    policy_namespace TEXT NOT NULL UNIQUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Human users, authenticated by an OIDC provider (issuer + subject).
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    issuer          TEXT NOT NULL,
    subject         TEXT NOT NULL,
    email           TEXT,
    status          TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

-- Services and automation, authenticated by Ed25519 request signatures.
-- organization_id is NULL for platform services (control plane, evaluators,
-- SecAgg coordinators, key brokers operated by the platform).
CREATE TABLE service_accounts (
    id              TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES organizations(id),
    kind            TEXT NOT NULL CHECK (kind IN ('control', 'evaluator', 'secagg', 'keybroker', 'automation')),
    public_key      TEXT NOT NULL UNIQUE,
    -- Where the service receives messages (key brokers, evaluators).
    url             TEXT,
    status          TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles of users and service accounts within organizations.
CREATE TABLE memberships (
    principal_id    TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    role            TEXT NOT NULL CHECK (role IN ('organization_admin', 'security_admin', 'data_owner',
                                                  'model_owner', 'ml_developer', 'auditor', 'operator')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, organization_id, role)
);

CREATE TABLE projects (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

-- Organizations collaborating in a project (the owner is a member too).
CREATE TABLE project_members (
    project_id      TEXT NOT NULL REFERENCES projects(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    added_by        TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, organization_id)
);

-- Asset registry: metadata only.
CREATE TABLE assets (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    kind            TEXT NOT NULL CHECK (kind IN ('dataset', 'model', 'adapter', 'checkpoint', 'program', 'artifact')),
    name            TEXT NOT NULL,
    digest          TEXT NOT NULL,
    size_bytes      BIGINT,
    media_type      TEXT,
    storage_uri     TEXT,
    policy          JSONB NOT NULL,
    lineage_root    TEXT NOT NULL,
    parents         JSONB NOT NULL DEFAULT '[]',
    key_ref         JSONB,
    status          TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    UNIQUE (organization_id, name)
);

-- Explicit sharing: the owner approves an asset for a project and purpose.
-- Ownership never moves.
CREATE TABLE asset_approvals (
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    project_id  TEXT NOT NULL REFERENCES projects(id),
    purpose     TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, project_id, purpose)
);

CREATE TABLE policies (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    project_id      TEXT NOT NULL REFERENCES projects(id),
    digest          TEXT NOT NULL,
    document        JSONB NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'withdrawn')),
    created_by      TEXT NOT NULL,
    approved_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE plans (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    project_id      TEXT NOT NULL REFERENCES projects(id),
    program_id      TEXT NOT NULL,
    spec_id         TEXT NOT NULL,
    program         TEXT NOT NULL,
    document        JSONB NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evaluators (
    id               TEXT PRIMARY KEY,
    service_account  TEXT NOT NULL UNIQUE REFERENCES service_accounts(id),
    url              TEXT NOT NULL,
    receipt_key      TEXT NOT NULL UNIQUE,
    backends         JSONB NOT NULL,
    profiles         JSONB NOT NULL,
    openfhe_version  TEXT NOT NULL,
    capacity         INTEGER NOT NULL CHECK (capacity > 0),
    status           TEXT NOT NULL CHECK (status IN ('ready', 'busy', 'draining', 'unhealthy')),
    last_heartbeat   TIMESTAMPTZ NOT NULL DEFAULT now(),
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id               TEXT PRIMARY KEY,
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    project_id       TEXT NOT NULL REFERENCES projects(id),
    plan_id          TEXT NOT NULL REFERENCES plans(id),
    spec_id          TEXT NOT NULL,
    program_id       TEXT NOT NULL,
    policy_id        TEXT REFERENCES policies(id),
    purpose          TEXT NOT NULL,
    source_assets    JSONB NOT NULL,
    requested_output TEXT NOT NULL,
    scheme           TEXT NOT NULL,
    backend          TEXT NOT NULL,
    profile          TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('created', 'planning', 'planned', 'waiting_for_approval',
                         'authorized', 'queued', 'running', 'verifying', 'succeeded', 'failed', 'cancelled')),
    evaluator_id     TEXT REFERENCES evaluators(id),
    -- The signed job grant for the scheduled evaluator.
    job_grant        JSONB,
    -- The evaluator's signed receipt, and the client's commitments.
    receipt          JSONB,
    evidence         JSONB,
    error            TEXT,
    initiated_by     TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    request_digest   TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, idempotency_key)
);

CREATE INDEX jobs_state ON jobs (state);

CREATE TABLE job_transitions (
    job_id     TEXT NOT NULL REFERENCES jobs(id),
    seq        INTEGER NOT NULL,
    from_state TEXT NOT NULL,
    to_state   TEXT NOT NULL,
    actor      TEXT NOT NULL,
    reason     TEXT,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, seq)
);

-- Owners' approvals for jobs waiting for approval.
CREATE TABLE job_approvals (
    job_id          TEXT NOT NULL REFERENCES jobs(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    approved_by     TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, organization_id)
);

-- Privacy ledgers: the hash-chained entries of each asset's ledger.
CREATE TABLE privacy_ledgers (
    asset_id        TEXT PRIMARY KEY REFERENCES assets(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    genesis         JSONB NOT NULL,
    -- Set by an operator's recovery after a detected rollback: the ledger
    -- is treated as exhausted, so forgotten spending can never be reused.
    frozen_reason   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Services an asset's owner authorized to record privacy events for it
-- (SecAgg coordinators). No other service may spend its budget.
CREATE TABLE privacy_spenders (
    asset_id    TEXT NOT NULL REFERENCES privacy_ledgers(asset_id),
    service_id  TEXT NOT NULL REFERENCES service_accounts(id),
    granted_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, service_id)
);

CREATE TABLE privacy_entries (
    asset_id TEXT NOT NULL REFERENCES privacy_ledgers(asset_id),
    seq      BIGINT NOT NULL,
    entry    JSONB NOT NULL,
    PRIMARY KEY (asset_id, seq)
);

-- Append-only, hash-chained audit trail.
CREATE TABLE audit_events (
    seq             BIGINT PRIMARY KEY,
    event_id        TEXT NOT NULL UNIQUE,
    at              TIMESTAMPTZ NOT NULL,
    organization_id TEXT,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    project_id      TEXT,
    result          TEXT NOT NULL CHECK (result IN ('allowed', 'denied', 'succeeded', 'failed')),
    request_id      TEXT NOT NULL,
    refs            JSONB NOT NULL,
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL UNIQUE
);

CREATE TABLE audit_checkpoints (
    seq       BIGINT PRIMARY KEY,
    root      TEXT NOT NULL,
    signer    TEXT NOT NULL,
    signature TEXT NOT NULL,
    at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotent consumers: a message is applied once per consumer.
CREATE TABLE inbox (
    consumer    TEXT NOT NULL,
    message_id  TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome     JSONB NOT NULL,
    PRIMARY KEY (consumer, message_id)
);

-- Messages to other services, delivered at least once by a background
-- loop (consumers are idempotent).
CREATE TABLE outbox (
    message_id   TEXT PRIMARY KEY,
    recipient    TEXT NOT NULL,
    url          TEXT NOT NULL,
    envelope     JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT
);
CREATE INDEX outbox_pending ON outbox (created_at) WHERE delivered_at IS NULL;

-- Replay protection for signed service requests.
CREATE TABLE request_nonces (
    sender     TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (sender, nonce)
);
CREATE INDEX request_nonces_expiry ON request_nonces (expires_at);

-- Single-row lock serializing appends to the audit chain.
CREATE TABLE audit_head (
    id   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    seq  BIGINT NOT NULL,
    hash TEXT NOT NULL
);
INSERT INTO audit_head (id, seq, hash) VALUES (TRUE, 0, 'genesis');
