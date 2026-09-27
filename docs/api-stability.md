# API stability

What you can build on, and what may still change. It covers release 0.3.0.
Artifact formats (models, receipts, ledgers, checkpoints) are covered
separately in [compatibility.md](compatibility.md).

## Classes

| Class | Meaning |
|---|---|
| **Stable** | Will not change incompatibly within 0.3.x. An incompatible change in a later release follows the deprecation policy below. |
| **Frozen** | Stable, and also closed to incompatible change until a new major API version. Applies to Control Plane API v1. |
| **Experimental** | Supported and tested, but may change in a minor release (0.4, 0.5). Each change is listed in the CHANGELOG. |
| **Research only** | Exists only in research builds (`research-tfhe-rs`, `vfhe-research`). May change or disappear at any time. |
| **Internal** | Not an interface. Used between Encompute's own components. Do not call it. |

## Control Plane API v1: frozen

[docs/api.md](api.md) is the contract. It is frozen for 0.3.

Frozen means:

- No route, field, header, status code or error code in API v1 is
  removed or renamed.
- No field changes type or meaning.
- No request that succeeds today starts failing, except for security
  fixes (see below).
- New optional request fields, new response fields, new routes and new
  enum values may be added. Clients must ignore response fields they do
  not know.
- A breaking change goes to `/v2`. `/v1` keeps its meaning.

Security exception: if a v1 behavior is itself a vulnerability, it is
fixed in v1, and the fix is called out in the release notes and the
advisory.

Covered: every route in [api.md](api.md), the authentication headers
(`Authorization`, `Encompute-Sender`, `Encompute-Recipient`,
`Encompute-Timestamp`, `Encompute-Nonce`, `Encompute-Bind`,
`Encompute-Signature`), `Idempotency-Key`, the JSON error shape
`{code, message}`, the roles and the job states.

Not covered: `GET /metrics` metric names and labels (experimental), log
formats, and the database schema (internal; see
[compatibility.md](compatibility.md)).

## Deprecation policy

For anything stable or frozen:

1. A deprecation is announced in the CHANGELOG and the release notes, with
   the replacement.
2. The deprecated interface keeps working for at least one minor release
   after the announcement, and at least 6 months.
3. Where possible it warns: the CLI prints a warning on standard error,
   Python raises a `DeprecationWarning`, and the HTTP API adds a
   `Deprecation` header.
4. Then it is removed in a minor release, listed under "Breaking" in the
   CHANGELOG.
5. A frozen API version (`/v1`) is never removed within a major release of
   Encompute. It is retired only after its successor has been available
   for at least 12 months.

Experimental interfaces may change without a deprecation period, but
every change is in the CHANGELOG.

## Python SDK (`encompute`)

The names in `encompute.__all__` are the public API. Anything starting
with `_`, and any module not listed here, is internal.

### Stable

| Area | Names |
|---|---|
| Compile and run | `compile` (`precision`, `verification`, `purpose`, `name`), `load`, `Model` (`run` and calling, `test`, `explain`, `bench`, `privacy`, `save`, `name`, `eir`, `inputs`, `semantics`, `parameters`, `security`), `TestReport` |
| Types | `secret`, `public`, `Secret`, `Tensor`, `ExactType`, `bool_`, `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` |
| Operations | `cast`, `dot`, `lookup`, `matvec`, `maximum`, `minimum`, `poly`, `select`, `sigmoid`, `square`, `sum` |
| Confidentiality | `Party`, `Asset`, `asset`, `confidential`, `reveal`, `publish`, `secure_aggregate`, `DP`, `DiscreteGaussian` |
| Planning | `Project` (`data`, `model`, `train`, `plan`), `ProjectAsset`, `Training`, `Privacy`, `PlanningFailed` |
| Errors | `EncomputeError` (`.code`, `.message`). Error codes are stable: [errors.md](errors.md) |
| Build probes | `has_openfhe`, `has_exact`, `__version__` |
| Control plane client | `Client`, `ControlError`, and the objects `Client` returns (`encompute.client.Project`, `Job`, `RunResult`). A thin client of the frozen API v1 |

### Experimental

| Area | Names |
|---|---|
| Fine-tuning | `Project.finetune`, `encompute.torch`: `wrap_model`, `private_dataset`, `private_text_dataset`, `TextDataset`, `huggingface`, `import_model`, `LoRAConfig`, `apply_lora`, `layout`, `layout_digest`, `get_flat`, `set_flat`, `build`, `TinyClassifier`, and `FineTuneResult` (`infer`, `lineage`, `export_adapter`, `export_peft`, `resume`, `summary`, `close`) |
| Confidential Space jobs | `encompute.torch.job` (`prepare`, `verify`), `python -m encompute.torch.cs_worker` |

These are tested end to end, but their arguments may still change as more
model architectures and TEEs are added.

### Research only

| Name | Note |
|---|---|
| `has_tfhe` | Reports whether this is a research build with TFHE-rs. |
| `compile(verification="required")` | Compiles in every build; verifying the proof needs the `vfhe-research` build. |

### Development only

`encompute.torch.job.Local`, the mock attester (`ENCOMPUTE_ATTESTER=mock`)
and the simulated launcher are for rehearsals and tests. They are not an
interface for production use.

### Internal

`encompute._native`, `_frontend`, `_privacy`, `_project` (import from
`encompute` instead), and the `encompute.torch` modules `dpsgd`, `lora`,
`models`, `tasks`, `tensors`, `worker`, `infer`, `finetune` (except
`FineTuneResult` above), `hf` (except `huggingface` and `import_model`).
`trace` and `SecretSpec` are importable but not exported.

## Command-line interface (`encompute`)

Command names, flags, exit codes and the `error[CODE]: message` format are
the interface. Human-readable output may change; scripts should use
`--json` where it exists, or the exit code.

| Class | Commands |
|---|---|
| Stable | `compile`, `run` (including `--remote`), `test`, `explain`, `bench`, `audit`, `keys generate`, `serve`, `verify`, `transcript`, `info`, `privacy explain`, `privacy graph`, `privacy budget`, `plan`, `check`, `aggregate identity`, `aggregate serve`, `aggregate join`, `aggregate verify`, `aggregate coordinator-policy`, `trust init`, `trust authorize`, `trust revoke`, `trust add`, `trust report`, `trust lineage`, `trust graph`, `attest verify`, `attest policy`, `keys protect`, `keys rotate`, `keys revoke`, `keys rewrap`, `keys rotate-root`, `keys serve`, `workload keys` |
| Stable (clients of API v1) | `login`, `projects list`, `projects show`, `projects create`, `projects add-member`, `assets list`, `assets show`, `assets register`, `assets approve`, `assets revoke`, `assets lineage`, `jobs submit`, `jobs run`, `jobs status`, `jobs list`, `jobs cancel`, `trust report JOB`, `audit list` |
| Experimental | `train`, `lineage`, `export` |
| Research only | `verify --proof --evaluation-keys` (needs `vfhe-research`); `--backend tfhe-rs` anywhere (needs `research-tfhe-rs`) |
| Development only | `attest mock-root`, `attest simulate-launcher`, `--mock-root`, `--development` (on `attest policy`, `aggregate coordinator-policy` and `keys protect`), `plan --allow-development`, `keys serve` without `--kek` or `--root-key` |
| Debugging | `keys challenge`, `keys release`, `workload attest` |

`encompute verify` exit codes are stable: 0 when the signature verifies
against a trusted key and the artifact, request and response bindings were
checked; 3 when some of them were not given; 1 when a check failed; 2 on
an error. Other commands exit 0 on success, 1 on a failed check, 2 on an
error.

### `encompute-control`

| Class | Commands |
|---|---|
| Stable | `serve`, `migrate`, `verify-state`, `bootstrap`, `recover`, `public-key` |
| Development only | `dev-token` (refused in production mode) |

The environment variables in [deployment.md](deployment.md) are stable.

### `encompute-evaluator`

| Class | Interface |
|---|---|
| Stable | `serve` with `--listen`, `--backend`, `--approx-backend`, `--exact-backend`, `--workers`, `--identity`, `--attestation`; the environment variables in [deployment.md](deployment.md) |
| Internal | `worker` (started by `serve`) |
| Research only | `--backend tfhe-rs`, `ENCOMPUTE_RESEARCH_EXACT_BACKEND` |

## Evaluator HTTP API: experimental

The evaluator's HTTP API is used by Encompute clients (`run --remote`,
the SDK, the control plane's clients). It is versioned by path (`/v1`) and
by `PROTOCOL_VERSION` in `GET /v1/info`, but it is not frozen. Clients and
evaluators must run the same Encompute minor release.

| Route | Purpose |
|---|---|
| `GET /v1/info` | Backends, protocol version, receipt key |
| `GET /metrics` | Prometheus metrics (requests, jobs, evaluation-key cache) |
| `GET /v1/attestation` | The attestation record the evaluator runs under (404 if none) |
| `POST /v1/programs` | Upload a program (`.eir` text); returns its program ID |
| `POST /v1/programs/{program}/keys` | Register evaluation keys |
| `GET /v1/programs/{program}/keys/{key}` | Is this key registered? |
| `POST /v1/programs/{program}/jobs` | Submit encrypted inputs (with a job grant when a control plane manages the evaluator) |
| `GET /v1/jobs/{job}/result` | The encrypted result |
| `GET /v1/jobs/{job}/receipt` | The signed execution receipt |
| `GET /v1/jobs/{job}/proof` | The execution proof (research build; 404 if none) |

The key broker's HTTP API (`POST /v1/challenge`, `/v1/attest`,
`/v1/release`, `/v1/messages`; `GET /live`, `/ready`) is experimental in
the same way.

## Rust crates: internal

Every Rust crate is internal. Encompute does not publish them to
crates.io, and their types, functions and features may change in any
release. Build on the
Python SDK, the CLI or the HTTP APIs instead.

This includes the crates that other documents mention by name, such as
`encompute-verification`, `encompute-attestation` and
`encompute-keybroker`. Their serialized formats are covered by
[compatibility.md](compatibility.md); their Rust APIs are not.

Cargo features:

| Feature | Class |
|---|---|
| `openfhe` | Stable: the production build |
| `research-tfhe-rs` | Research only. Never in a commercial build |
| `vfhe-research` | Research only |
| `encompute-privacy/insecure-deterministic-noise`, `encompute-privacy/failpoints` | Internal: tests only. Never in a release build |
