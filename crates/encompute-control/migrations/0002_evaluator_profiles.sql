-- Encompute control plane, schema version 2: evaluator machine profiles and
-- cost-aware scheduling.
--
-- A machine profile is what an evaluator says about itself. It steers
-- placement and completion estimates only, never a security decision: an
-- evaluator that overstates its hardware only attracts more of the jobs it
-- is already allowed to run.

ALTER TABLE evaluators
    ADD COLUMN cpu_model          TEXT,
    ADD COLUMN logical_cores      INTEGER CHECK (logical_cores > 0),
    ADD COLUMN memory_bytes       BIGINT  CHECK (memory_bytes > 0),
    -- The calibrated cost profile the evaluator was benchmarked under.
    ADD COLUMN benchmark_profile  TEXT,
    -- Worker threads the evaluator uses for one job's gates.
    ADD COLUMN max_parallel_gates INTEGER CHECK (max_parallel_gates > 0);

ALTER TABLE jobs
    -- The plan's work estimate (bootstrapped gates; 0 when unknown).
    ADD COLUMN estimated_gates BIGINT NOT NULL DEFAULT 0 CHECK (estimated_gates >= 0),
    -- The scheduler's completion estimate on the chosen evaluator.
    ADD COLUMN estimated_ms    BIGINT CHECK (estimated_ms >= 0);
