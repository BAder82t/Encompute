# Artifact compatibility

Encompute writes many durable artifacts: compiled models, keys and
ciphertexts, receipts, trust bundles, privacy ledgers, training records,
database rows. This page says, for each one, which versions can read it,
what needs a migration, and what fails closed.

It describes release 0.3.0. [Changes since 0.3.0-rc.3](#changes-since-030-rc3)
lists what an rc.3 installation must rebuild, re-key or upgrade. For which
capabilities are supported at all,
see [support-matrix.md](support-matrix.md). For API and CLI stability, see
[api-stability.md](api-stability.md).

## Principles

1. **Fail closed.** A reader that meets a version it does not know refuses
   the artifact with a stable error code. It never guesses, and never
   falls back to a weaker check.
2. **One version per reader, today.** In 0.3 every reader accepts exactly
   one version of each format. No reader accepts a range, and none reads
   an older version. This is strict on purpose during the release
   candidate, and it is the main thing the policy below must relax.
3. **You never retrain because internal metadata changed.** Trained
   weights, adapters and checkpoints are your data. A change to how
   Encompute describes them (a spec, a record, a header, a layout) must
   come with a migration that re-issues the metadata around the same
   weights, or with a reader that still accepts the old version. It must
   never make you run training again, and it must never re-spend privacy
   budget.
4. **Signed evidence is never rewritten.** Receipts, privacy receipts,
   authorizations, attestation records and adapter records are signed by
   the party that made them. A migration cannot re-sign them. Future
   releases must keep reading every signed evidence version they
   produced, or verify it with the release that produced it.
5. **Recompiling is allowed; retraining and re-spending are not.** Where
   an artifact is a pure function of its source (a compiled model from its
   program), the migration is to rebuild it.
6. **Version fields are in the bytes.** Every format has a version field,
   a versioned magic, or a versioned domain-separation tag in its hash.
   IDs with a prefix (`encspec1:`, `encplan1:`, `enctrain1:`) carry the
   ID scheme's version in the prefix.

## Release-to-release rules

| Change | What we promise |
|---|---|
| Patch release (0.3.x) | No format changes. Everything written by 0.3.y reads in 0.3.z. |
| Minor release (0.4, 0.5, …) before 1.0 | Formats may change. Each change is listed in the CHANGELOG under "Breaking", with its migration. Signed evidence from the previous minor release stays verifiable. |
| 1.0 and later | Readers accept the current and the previous major version of every format. |

## Formats

"Reads" is what this release accepts. "On mismatch" is the error a reader
returns for another version. "Migration" is what to do when the version
changes.

### Compiled model artifacts (`.encompute`)

| | |
|---|---|
| Version | `artifact_format` in `manifest.json`: **5** (`crates/encompute-runtime/src/artifact.rs`). History: 1 was the 0.1 layout, 2 the CKKS-only 0.2 layout, 3 added exact plans, 4 `verification.json`, 5 `policy.json`. |
| Reads | Format 5 only. |
| On mismatch | ENC1401: "unsupported artifact format N (this Encompute reads format 5); recompile". |
| Also checked | Every file's hash. Then the loader recompiles `program.eir` and requires the compiler, plan, parameter and crypto entries, and every generated file, to be byte-identical to what this build produces. Any difference is ENC1401. |
| Migration | Recompile from the source (`encompute compile`). `program.eir` inside the artifact is the source of truth, so no other input is needed. |
| Consequence | Any change to compiler output invalidates old artifacts, even when the format number stays 5. The new artifact can have a different plan, spec ID and parameters, so keys and receipts made for the old one do not carry over. |
| Refused sources | A program whose secure aggregation combines privacy-budgeted assets without `dp` no longer compiles (ENC2203), whatever the output's destination: the aggregate is always released to the coordinator. Because the loader recompiles `program.eir`, an rc.3 artifact with such an aggregation is refused on load with the same error. Add `dp` to the aggregation. |

Planned: `encompute migrate` should rebuild an artifact from its
`program.eir`, show whether the program ID, spec ID and parameters
changed, and refuse silently changed semantics.

### ExecutionSpec (`encspec1:`)

| | |
|---|---|
| Version | `SPEC_VERSION = 1` (`crates/encompute-verification/src/spec.rs`), plus `plan_version`. |
| ID | SHA-256 over the domain tag `encompute.execution-spec.v1` and the canonical JSON. Optional fields (policy and privacy policy IDs) are left out when absent, so specs without them keep their IDs. |
| Reads | Version 1. The version is not checked by itself: it is part of the ID, so another version gives another ID. |
| On mismatch | A receipt for another spec ID fails with ENC1606. An attestation for another spec ID fails with ENC2002. |
| Migration | None needed for readers. A new spec version means new spec IDs: receipts, attestation policies and key-release policies bound to the old IDs must be reissued for new runs. Old receipts stay verifiable against the old spec. |

### ExactPlan

| | |
|---|---|
| Version | `EXACT_PLAN_VERSION = 1` (`crates/encompute-exact/src/lib.rs`), recorded in the artifact manifest, the execution spec and the semantic transcript. The plan itself has no version field. |
| Optimizer | `OPTIMIZER_VERSION = 1`. Provenance only: it is in the evaluator's program info and job response, never in any ID. The optimizer may change without changing any ID or result. |
| Reads | Plan version 1, through the artifact check above. |
| On mismatch | ENC1401 (artifact). |
| Migration | Recompile the artifact. |
| BGV profile | The BGV profile's failure probability now reads "negligible (noise budget enforced; not zero)" instead of "0 (exact modular arithmetic)" (`crates/encompute-exact/src/bgv.rs`). The profile is hashed into `parameter_set_id`, so every BGV artifact changes parameter set ID. Plans whose worst-case noise growth exceeds the BGV budget, and bitwise logic on integers, are no longer selected for BGV. |

CKKS plans use `PLAN_VERSION = 1` and `PARAMETER_SELECTOR_VERSION = 1`
(`crates/encompute-ckks/src/lib.rs`), with the same rules.

### Planner plans (`encplan1:` PlanId)

| | |
|---|---|
| Version | `PLAN_VERSION = 1` (`crates/encompute-planner/src/planner.rs`). ID tag `encompute.confidential-execution-plan.v1`. A plan made in sovereign custody carries `context.custody` (each source's asset, owner organization and key broker) and a `key_custody` requirement per source, both in the PlanId; other plans do not serialize them, so their PlanIds are unchanged. |
| Reads | Version 1 only. |
| On mismatch | ENC2402 (plan invalid), from the independent validator. |
| Migration | Regenerate with `encompute plan`. A new plan has a new PlanId, so aggregation rounds and trust bundles bound to the old one must be re-approved for new runs. |

### TrainingSpec (`enctrain1:`)

| | |
|---|---|
| Version | `SPEC_VERSION = 2` (`crates/encompute-training/src/spec.rs`). Domain tags `training-spec.v1`, `training-run.v1`, `training-participant.v1`. Version 2 binds the key brokers and their grant-signing keys (`key_brokers`), the coordinator's adapter-record key (`coordinator_key`) and the initial adapter (`initial_adapter_digest`). The optional `asset_brokers` (key ID to broker ID) binds each key to the broker that holds it, with `broker_organizations` (broker ID to its owner, a participant or the model owner). A spec with them may name several brokers, provided `asset_brokers` binds exactly the keys the spec's workers acquire (`TrainingSpec::key_ids`: the base model, `checkpoints` and `adapters`, and for each contributing participant `MODEL.PARTY`, `dataset-DATASET`, `adapters.PARTY` and `contribution-PARTY`), names only brokers in `key_brokers`, uses each of them, and no two brokers share a grant-signing key. A participant's own keys (dataset, contribution) are bound to its own broker when it runs one, else to the model owner's, never to another participant's; the model owner's keys to the model owner's broker. Without them, a spec names exactly one broker. When absent they are not serialized, so the IDs of specs written before them are unchanged. A key named twice in `asset_brokers`, `broker_organizations` or `key_brokers` is refused when the spec is read. `base_model.architecture` must name a factory the worker image ships (`encompute.torch.models:tiny_classifier`, or `encompute.torch.hf:from_config` with the package's own `config.json`). A dataset's `privacy_units` is optional: when present, it is a figure the owner approved for publication, not a count of the data. |
| Reads | Version 2 only. |
| On mismatch | ENC2501. A spec that names another model factory is also ENC2501. |
| Migration | **Needs `encompute migrate`** (planned). A spec binds the model package, datasets, tokenization, LoRA or PEFT configuration, layout and every DP-SGD setting. A new spec version must be derived from the old spec and the owners' existing approvals, without retraining. |

### Ciphertext and key envelopes

| | |
|---|---|
| `ENCM` envelopes | Magic `ENCM`, `FORMAT_VERSION = 1` (`crates/encompute-protocol/src/lib.rs`). Unchanged since 0.2.0. Bound to kind, scheme, backend, backend version, parameter set, program and key. |
| On mismatch | Bad magic, truncation or checksum: ENC1601. Another format version, kind, scheme, backend or backend version: ENC1602. Another parameter set: ENC1603. Another program: ENC1604. Another key: ENC1605. |
| `ENCBINF1` (OpenFHE exact keys and ciphertexts) | `ENVELOPE_VERSION = 1` (`crates/encompute-openfhe-exact/src/lib.rs`). Bound to the backend, the profile `BINFHE_STD128_GINX_BITS_V1`, OpenFHE 1.5.1, the client's key ID and the type. |
| On mismatch | Another envelope version: ENC1601. Another backend, profile or OpenFHE version: ENC1603. |
| Evaluator wire protocol | `PROTOCOL_VERSION = 1`, advertised in `GET /v1/info`. |
| Migration | None. Ciphertexts and evaluation keys are short-lived: regenerate keys (`encompute keys generate`) and re-encrypt. A new OpenFHE version or parameter profile always means new keys. |

Keys and ciphertexts are the one artifact type that is never migrated.
Clients and evaluators must run the same Encompute minor release.

### Execution receipts, transcripts and proofs

| | |
|---|---|
| Receipts | `RECEIPT_VERSION = 3` (`crates/encompute-verification/src/receipt.rs`). Version 3 added the optional attestation binding. |
| Reads | Version 3 only. Versions 1 and 2 (written by earlier development builds, never by a release) are refused. |
| On mismatch | ENC1606: "receipt version N (this Encompute reads 3)". |
| Semantic transcripts (`enctrace1:`) | `TRANSCRIPT_VERSION = 1`, format `EncomputeProofTranscriptV1`. Another version or format: ENC1702. |
| Execution proofs | Magic `ENCP`, `PROOF_VERSION = 1` (research build). Another version: ENC1801. |
| Migration | None possible: receipts are signed by the evaluator. From 0.3.0 on, later releases must keep reading receipt version 3. |

### Trust graph records

| | |
|---|---|
| Trust bundle | `GRAPH_VERSION = 1` (`crates/encompute-trust/src/graph.rs`). Another version: ENC2303 ("unsupported version"). |
| Authorizations and revocations | `AUTHORIZATION_VERSION = 1`. Another version: ENC2302. Signed by owners. |
| Migration | **Needs `encompute migrate`** (planned) for the bundle: a bundle is rebuilt from its evidence, so a migration can re-derive a new-version bundle from the same signed evidence. The signed evidence inside (authorizations, receipts, attestations, adapter records) is not rewritten. |

### Differential privacy: PrivacyReceipt, ledgers, state anchor

| | |
|---|---|
| PrivacyReceipt | `RECEIPT_VERSION = 1` (`crates/encompute-privacy/src/release.rs`). Another version: ENC2204. Signed by the coordinator. |
| File ledgers | `LEDGER_VERSION = 1` (`crates/encompute-privacy/src/ledger.rs`), checked on the genesis entry. Another version: ENC2202. Hash-chained. |
| Database ledgers | PostgreSQL tables, versioned by the schema migrations below. |
| State anchor | `ANCHOR_VERSION = 2` (`crates/encompute-control/src/anchor.rs`), signed in the domain `encompute.state-anchor.v2`: the audit root and the governance event log's size and head, a constant size: security-negative transitions and the privacy ledgers' checkpoints are log events (`privacy.ledger_checkpoint`), so it grows with neither assets, revocations nor spends. Version 1 (0.3.0 and earlier: sets of every revoked, disabled, ended, withdrawn, removed and expired ID) is read only to migrate it, once, at the first start: only if the database passes every check 0.3.0 made, its sets become log events (`anchor.genesis`, then one `migrated.<set>` event per ID, `ledger.frozen`, `row.lost`, and one `privacy.ledger_checkpoint` per ledger) in one transaction, then the anchor is replaced compare-and-set. A crash in between resumes at the next start. Any other version: ENC2202, and the control plane refuses to start. The anchor store also holds the log's mirror: segments named `{n}-{from}-{to}` (write order, first and last event), each the events as JSON lines (position, chain hash, the event as hashed), in `governance-log/` next to a directory anchor or under `<path>-glog/` in OpenBao/Vault KV. |
| Sensitivity | A unit inside a party (record, user, patient, device) without Poisson sampling is now charged sensitivity `2 × clip_norm`, as an organization is; only DP-SGD (Poisson sampling) charges `1 × clip_norm`. Receipts and ledger entries written from this release record the doubled sensitivity. An rc.3 PrivacyReceipt for such a unit no longer matches its release (ENC2204). Ledger entries rc.3 wrote keep the sensitivity they recorded, so spend recorded then was charged about half the true sensitivity. |
| Epsilon | Each reported epsilon is raised by a relative margin of 1e-12, and the Rényi curve carries a rounding allowance, so values differ from rc.3's around the 12th significant digit. Recorded epsilons are not recomputed on read. |
| Migration | Spent budget must never be lost or reset. **File ledgers need `encompute migrate`** (planned) if their format changes: the migration must append to the chain, not rewrite it, so owners' checkpoints still verify. A new anchor version must be written by the control plane, next to the old one, on first start. |

### Checkpoints and adapter records

| | |
|---|---|
| Checkpoints | `CHECKPOINT_VERSION = 1` (`crates/encompute-training/src/checkpoint.rs`). Another version: ENC2502 (reported as "the checkpoint is corrupted"). |
| Adapter records | `ADAPTER_VERSION = 1` (`crates/encompute-training/src/adapter.rs`), tag `adapter-record.v1`. Another version: ENC2501. Signed. |
| Sealed assets | File magic `ENCSEAL1` (in the AEAD associated data) and header `ASSET_VERSION = 1` (`crates/encompute-training/src/seal.rs`). Another magic or version: ENC2502. |
| Adapter layout | `LAYOUT_VERSION = 1` (`crates/encompute-training/src/layout.rs`, duplicated in `python/encompute/torch/lora.py`). Another version: ENC2501. |
| Canonical tensor files | Magic `ENCTENS1`. Another magic: ENC2501. Pickles are refused before loading. |
| Worker evidence | `WORKER_EVIDENCE_VERSION = 2` (`crates/encompute-training/src/worker.rs`). Version 2 adds the input adapter and its digest, the training configuration's digest and the seed. Another version: ENC2501. |
| Confidential Space job descriptors | `kind` `encompute.confidential-training-job.v1`, `version` **2** (`JOB_VERSION`, `python/encompute/torch/cs_worker.py`). Version 2 carries the approved plan and, after round 1, the input adapter's signed record; the training configuration comes from the spec. Another version: the worker refuses the job ("not a confidential training job descriptor (version 2)"). Descriptors hold no secret: regenerate them. |
| Hugging Face model packages (`enchf1:`) | `PACKAGE_VERSION = 1` (`crates/encompute-training/src/hf.rs`). Another version: ENC2504. The package also binds the major.minor versions of Transformers, PEFT and PyTorch: other library versions are refused with ENC2504. |
| Migration | **Needs `encompute migrate`** (planned) for checkpoints, sealed-asset headers, the adapter layout, tensor files and model packages. The adapter weights inside must be carried over unchanged, and the migration must check the privacy ledgers so a resumed run can never roll back spent budget. Adapter records and worker evidence are signed and stay readable instead. |

A Hugging Face package pinned to Transformers 4.46 is refused by a worker
running Transformers 4.47. That is deliberate: library code is part of
what the owners approved. To move to a new library version, re-import the
model (a new package, a new spec). Existing adapters keep their lineage.

### Secure aggregation

| | |
|---|---|
| Versions | Plan, spec, round, receipt and protocol versions are all 1; protocol `secagg-bonawitz17` (`crates/encompute-secagg/src/round.rs`). |
| On mismatch | Spec or protocol (`encagg1:`): ENC2106. Round (`encround1:`): ENC2102. Aggregation receipt: ENC2104. |
| Party state (`aggregate join --state`) | JSON: the global `sequence` and the ledger `checkpoints` as before, plus `sequences`, the last round joined per aggregation spec ID. The older global `sequence` stays a floor for every spec. A file holding only a number (the oldest format) still reads. Updates take an exclusive lock on `STATE.lock` and replace the file atomically. Sequences above 2^53 − 1 are refused (ENC2102). |
| Migration | None. A round is short-lived: start a new round with the new version. Aggregation receipts are signed and stay readable. An rc.3 `--state` file is read as is and gains `sequences` on the next join. |

### Attestation and key broker state

| | |
|---|---|
| Attestation | Evidence, binding and record versions are 1: another version is ENC2001. Attestation policies (`POLICY_VERSION = 1`): ENC2002. Grants (`GRANT_VERSION = 1`) are written, and the version is not checked on read yet. |
| Broker state | No version field. Unknown fields are refused (ENC2004), so a newer broker's file does not load in an older broker. The state now carries `generation` (incremented by every save) and `mac` (HMAC-SHA256 over the rest of the state, under a key derived from the KEK). A broker opens only a state whose MAC verifies (ENC2004). Development plaintext storage has no KEK, so its state has no MAC. |
| Wrapped KEK | `WRAPPED_KEK_FORMAT = 1` (`crates/encompute-keybroker/src/root.rs`). Another format: ENC2004. |
| Migration | A KEK-protected state written by rc.3 has no MAC and is refused. Run `encompute keys upgrade-state --broker FILE` with the broker's usual `--kek` or `--root-key` options: it prints the release policies, mode and organization; check them against your own records, since an unauthenticated file may have been edited, then rerun with `--confirm` to add the MAC. **Broker state needs `encompute migrate`** (planned) for any future format change, with a version field added first. `encompute keys rewrap` and `keys rotate-root` re-wrap keys without changing formats. |

### Control plane: database schema and audit events

| | |
|---|---|
| Schema | Versioned SQL migrations embedded in the binary (`crates/encompute-control/migrations/`: `0001_initial.sql`, `0002_evaluator_profiles.sql`, `0003_consent_bound_sharing.sql`, `0004_approval_identity.sql`, `0005_public_sector_governance.sql`, `0006_sovereign_custody.sql`). Each applied migration is recorded with its checksum in `schema_migrations`. Shipped migrations are never edited. |
| Applied by | `encompute-control migrate`, and automatically at `serve` and `recover`, under a PostgreSQL advisory lock. Forward only: there are no down migrations. |
| Reads | Any older schema (it is migrated forward). |
| On mismatch | A database newer than the binary: ENC1602, "the database schema (version N) is newer than this control plane". An applied migration whose checksum changed: ENC1602. |
| Audit events | No version field. The version is in the hash domain `encompute.audit-event.v1`. A broken chain: ENC2301. |
| 0003 | `0003_consent_bound_sharing.sql` adds `asset_approval_members` (an approval covers the organizations that were project members when it was given) and a `status` (`invited` or `active`) on `project_members`. Existing approvals cover the members that had joined by then (each such grant dated from its approval, so a backup migrated twice gets the same rows), and existing memberships stay active. An organization added later sees nothing of an asset until its owner approves again. |
| Downgrade | Unsupported. A version-2 state anchor is refused by every earlier release (its fields are unknown to them: the control plane does not start), and the governance log's events, ledger checkpoints included, are not read by them; no earlier release can hold a ledger's floor. To roll back, restore the database backup and the anchor copy taken before the upgrade, together. Schema version 4 refuses an 0.3.0-rc.3 control plane, and once the 0.3.0-rc.4 control plane has written its new anchor sets (ended jobs, withdrawn approvals, removed memberships and roles) an rc.3 binary cannot read the anchor. To roll back, restore the database backup taken before the upgrade together with its matching anchor; the anchor check refuses an older database otherwise (ENC2202, then `encompute-control recover`). |

### Control Plane API v1

The HTTP contract is versioned by path. See
[api-stability.md](api-stability.md).

## What fails closed, in one table

| Artifact | Error on an unknown version |
|---|---|
| Compiled model | ENC1401 |
| `ENCM` envelope | ENC1602 (ENC1601 for bad bytes) |
| `ENCBINF1` envelope | ENC1601 |
| Execution receipt | ENC1606 |
| Semantic transcript | ENC1702 |
| Execution proof | ENC1801 |
| Planner plan | ENC2402 |
| Trust bundle | ENC2303 |
| Authorization, revocation | ENC2302 |
| PrivacyReceipt | ENC2204 |
| Privacy ledger, state anchor | ENC2202 |
| TrainingSpec, adapter record, layout, tensor file, worker evidence | ENC2501 |
| Checkpoint, sealed asset | ENC2502 |
| Hugging Face model package | ENC2504 |
| Confidential Space job descriptor | Refused by the worker (`JobRefused`, no code) |
| Aggregation spec / round / receipt | ENC2106 / ENC2102 / ENC2104 |
| Attestation evidence, binding, record | ENC2001 |
| Attestation policy | ENC2002 |
| Wrapped KEK, broker state | ENC2004 |
| Database schema newer than the binary | ENC1602 |

## Planned: `encompute migrate`

No artifact migration tool exists yet. Only the control plane's database
schema migrates today. `encompute migrate` is planned, and it needs to
handle exactly these artifact types:

| Artifact | What the migration does |
|---|---|
| Compiled model (`.encompute`) | Rebuild from `program.eir`; report changed program, spec and parameter IDs. |
| TrainingSpec | Derive the new-version spec from the old one; keep the owners' approvals linked. |
| Checkpoints | Re-issue the checkpoint around the same adapter weights; check the privacy ledgers first. |
| Sealed-asset headers | Re-seal the header; keep the payload and its key. |
| Adapter layout and canonical tensor files | Re-encode; the numbers must be identical. |
| Hugging Face model packages | Re-issue the package manifest over the same files and digests. |
| Trust bundles | Rebuild from the same signed evidence. |
| File privacy ledgers | Append a migration entry; never rewrite the chain. |
| Key broker state | Add a version field; carry wrapped keys over unchanged. |

Not migrated, by design: keys and ciphertexts (regenerate), aggregation
rounds (start a new one), and signed evidence (receipts, PrivacyReceipts,
authorizations, revocations, attestation records, adapter records, worker
evidence), which later releases must keep reading. Release candidates are
the exception: evidence an rc.3 build signed and that this release refuses
(worker evidence version 1, PrivacyReceipts with the old sensitivity) is
verified with rc.3.

## Changes since 0.3.0-rc.3

| Artifact | What changed | What to do |
|---|---|---|
| Compiled artifacts with budgeted aggregations and no `dp` | Refused at compile and load (ENC2203) | Add `dp` to the aggregation and recompile |
| BGV artifacts, keys and ciphertexts | New `parameter_set_id` (the profile's failure-probability text changed); some programs no longer select BGV | Recompile, then generate new keys (`encompute keys generate`) and re-encrypt |
| TrainingSpec | `SPEC_VERSION = 2`, new bound fields, allowlisted model factories | Regenerate the spec (new ID); owners approve it again. Checkpoints and adapter records bound to an rc.3 spec ID do not resume under it |
| Worker evidence | `WORKER_EVIDENCE_VERSION = 2` | Verify rc.3 evidence with rc.3 |
| Confidential Space job descriptors | Version 2 | Regenerate |
| Key broker state | `generation` and `mac` | `encompute keys upgrade-state`, then `--confirm` |
| PrivacyReceipts and ledgers | Doubled sensitivity for unsampled units inside a party; epsilon margin | rc.3 receipts for such units no longer verify; new entries charge the doubled sensitivity |
| Aggregation party state | Per-spec `sequences` | None: read as is |
| Control-plane database | Migration 0003 | Applied at `migrate`, `serve` or `recover` |
| Job submissions (`POST /v1/jobs`) | `source_assets` must equal the registered assets the program binds, each once, for every job; empty when it binds none. Jobs recorded before with other sources fail the trust report's `source assets` check | Bind the assets in the program (`asset "<asset ID>" ...`, `input ... asset "<asset ID>"`) or send an empty list |

## Known inconsistencies

These do not weaken fail-closed behavior, but they are rough edges for the
migration work:

- An `ENCBINF1` version mismatch is ENC1601, while an `ENCM` version
  mismatch is ENC1602 as `docs/errors.md` documents.
- A checkpoint version mismatch is reported as "corrupted".
- The attestation grant version is not checked on read.
- The evaluator's wire protocol version is advertised but not checked by
  clients.
- The `ExecutionSpec` version is checked only through the spec ID.
