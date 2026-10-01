-- Encompute control plane, schema version 16: governed jobs' privacy
-- reservations (governed projects, differential-privacy scopes, part 3).
--
-- A governed job whose program releases a differential-privacy aggregate
-- reserves its release in each source's scope (and so in its population)
-- when it starts, before any noise exists. The reservation is the job's
-- (one entry per job and scope, identified by the job), so starting twice,
-- or the coordinator reporting the same release, charges once.

CREATE TABLE job_privacy_reservations (
    job_id      TEXT NOT NULL REFERENCES jobs(id),
    scope_id    TEXT NOT NULL REFERENCES privacy_scopes(id),
    -- The source asset the scope serves.
    asset_id    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    -- The entry's position in the scope's ledger.
    scope_seq   BIGINT NOT NULL CHECK (scope_seq > 0),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, scope_id)
);

CREATE INDEX job_privacy_reservations_scope ON job_privacy_reservations (scope_id);
