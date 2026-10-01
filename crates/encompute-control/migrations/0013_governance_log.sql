-- Encompute control plane, schema version 13: the governance event log
-- (governed projects, part 8), whose head the state anchor holds.
--
-- Every security-negative governance transition (a revoked or expired
-- asset, a disabled service account or user, a cancelled or failed job, a
-- withdrawn approval or ended grant, a removed project membership or
-- organization role, an issued or revoked owner authorization, a retired
-- purpose, a revoked governance key) appends one event here in the same
-- transaction as the change. A governance-key revocation appends one event
-- to its organization and one to each governed project the organization
-- takes part in.
--
-- - Each event belongs to one partition: `p:<project>` (governed projects
--   only), `o:<organization>` or `platform`. Standard projects' events go
--   to the organization's partition, so standard projects are unchanged.
-- - `body` is the event as hashed: identifiers, the kind of transition and
--   when, never a storage location, a key reference, a person's identifier
--   or private metadata, so every member of the partition may read it.
-- - All events form one hash chain in `gseq` order (`prev_hash`, `hash`);
--   `governance_head` holds its head and serializes appends.
-- - Each partition is an RFC 6962 Merkle tree over its events' leaf
--   hashes. `governance_tree_nodes` keeps its complete subtrees (each
--   written once, never changed), so a root, an inclusion proof or a
--   consistency proof needs O(log n) rows.
-- - `governance_checkpoints` keeps the control plane's signed checkpoints
--   of a partition, `checkpoint_witnesses` the members' countersignatures,
--   `revocation_heads` the owners' signed revocation heads.
--
-- Lock order: `governance_head` is taken immediately before `audit_head`,
-- which stays last. The audit append takes it first, so a transaction that
-- records a governance event and an audit event, in either order, always
-- locks the two heads in the same order.
--
-- Everything here is append-only: UPDATE, DELETE and TRUNCATE are refused
-- (the head row is only ever moved forward by an append). The triggers
-- stop the control plane and anyone using its credentials as granted; they
-- do not stop a database superuser or the table owner, who can disable
-- them (as with the audit chain). Against those, the anchored head (the
-- state anchor holds the log's size and head, and every start checks the
-- log still contains it) and the members' witnessed checkpoints are the
-- defence.
--
-- `governance_anchor_genesis` keeps the signed state anchor of an earlier
-- release (version 1, which held the sets of negative IDs) that was
-- migrated into the log: the `anchor.genesis` event records its digest,
-- and the following `migrated.<set>` events its IDs.

CREATE TABLE governance_events (
    gseq        BIGINT PRIMARY KEY CHECK (gseq > 0),
    partition   TEXT NOT NULL,
    pseq        BIGINT NOT NULL CHECK (pseq > 0),
    kind        TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    org_id      TEXT,
    body        JSONB NOT NULL,
    leaf_hash   TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (partition, pseq)
);

CREATE INDEX governance_events_kind ON governance_events (kind, subject_id);
-- A project's membership events (the members at any size are derived from
-- them) without reading the whole partition.
CREATE INDEX governance_events_membership ON governance_events (partition, pseq)
    WHERE kind IN ('membership.added', 'membership.removed');
-- An organization's revocations in a project and the revocation head
-- events about them (an owner's head covers its own revocations, which the
-- control plane folds without reading the whole partition).
CREATE INDEX governance_events_revocations ON governance_events (partition, org_id, pseq)
    WHERE kind IN ('authorization.revoked', 'asset.revoked', 'asset.expired',
                   'purpose.retired', 'governance_key.revoked',
                   'revocation_head.signed');
-- A revoked authorization's signed document ID (startup and run-time
-- checks look it up).
CREATE INDEX governance_events_authorization ON governance_events ((body #>> '{refs,authorization_id}'))
    WHERE body #>> '{refs,authorization_id}' IS NOT NULL;

-- Privacy ledger checkpoints are governance log events
-- (`privacy.ledger_checkpoint`, subject = the asset). The latest one of an
-- asset is its floor at startup and on every spend: one index probe, newest
-- first, never a scan or a sort of the asset's checkpoints.
CREATE INDEX governance_events_ledger_checkpoint ON governance_events (subject_id, gseq DESC)
    WHERE kind = 'privacy.ledger_checkpoint';

-- Single-row lock serializing appends to the chain.
CREATE TABLE governance_head (
    id   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    gseq BIGINT NOT NULL,
    hash TEXT NOT NULL
);
INSERT INTO governance_head (id, gseq, hash)
    VALUES (TRUE, 0, '0000000000000000000000000000000000000000000000000000000000000000');

-- Complete subtrees: `hash` is the root of leaves
-- [idx * 2^level, (idx + 1) * 2^level) of the partition.
CREATE TABLE governance_tree_nodes (
    partition TEXT NOT NULL,
    level     INTEGER NOT NULL CHECK (level >= 0 AND level < 64),
    idx       BIGINT NOT NULL CHECK (idx >= 0),
    hash      TEXT NOT NULL,
    PRIMARY KEY (partition, level, idx)
);

CREATE TABLE governance_checkpoints (
    partition  TEXT NOT NULL,
    size       BIGINT NOT NULL CHECK (size >= 0),
    root       TEXT NOT NULL,
    gseq       BIGINT NOT NULL,
    signed     JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (partition, size)
);

CREATE TABLE checkpoint_witnesses (
    partition       TEXT NOT NULL,
    size            BIGINT NOT NULL,
    organization_id TEXT NOT NULL,
    signed          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (partition, size, organization_id)
);

CREATE TABLE revocation_heads (
    organization_id TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    seq             BIGINT NOT NULL CHECK (seq > 0),
    root            TEXT NOT NULL,
    at              BIGINT NOT NULL,
    signed          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, project_id, seq)
);

CREATE TABLE governance_anchor_genesis (
    gseq   BIGINT PRIMARY KEY,
    digest TEXT NOT NULL,
    anchor TEXT NOT NULL
);

CREATE FUNCTION encompute_governance_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'the governance event log is append-only (%)', TG_TABLE_NAME
        USING ERRCODE = 'check_violation';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER governance_events_append_only BEFORE UPDATE OR DELETE ON governance_events
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_tree_nodes_append_only BEFORE UPDATE OR DELETE ON governance_tree_nodes
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_checkpoints_append_only BEFORE UPDATE OR DELETE ON governance_checkpoints
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER checkpoint_witnesses_append_only BEFORE UPDATE OR DELETE ON checkpoint_witnesses
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER revocation_heads_append_only BEFORE UPDATE OR DELETE ON revocation_heads
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_anchor_genesis_append_only BEFORE UPDATE OR DELETE ON governance_anchor_genesis
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_head_append_only BEFORE DELETE ON governance_head
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_log_append_only();

CREATE TRIGGER governance_events_no_truncate BEFORE TRUNCATE ON governance_events
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_tree_nodes_no_truncate BEFORE TRUNCATE ON governance_tree_nodes
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_checkpoints_no_truncate BEFORE TRUNCATE ON governance_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER checkpoint_witnesses_no_truncate BEFORE TRUNCATE ON checkpoint_witnesses
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER revocation_heads_no_truncate BEFORE TRUNCATE ON revocation_heads
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_anchor_genesis_no_truncate BEFORE TRUNCATE ON governance_anchor_genesis
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();
CREATE TRIGGER governance_head_no_truncate BEFORE TRUNCATE ON governance_head
    FOR EACH STATEMENT EXECUTE FUNCTION encompute_governance_log_append_only();

-- The head only moves forward, one event at a time.
CREATE FUNCTION encompute_governance_head_forward() RETURNS trigger AS $$
BEGIN
    IF NEW.gseq <> OLD.gseq + 1 THEN
        RAISE EXCEPTION 'the governance log head moves forward one event at a time'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER governance_head_forward BEFORE UPDATE ON governance_head
    FOR EACH ROW EXECUTE FUNCTION encompute_governance_head_forward();
