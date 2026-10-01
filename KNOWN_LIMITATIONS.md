# Known limitations

What Encompute 0.3 does not do, does slowly, or does only under
assumptions. Read this before you put real data through it. These are
documented limitations, not vulnerabilities: see [SECURITY.md](SECURITY.md)
for what to report.

Related: [support matrix](docs/support-matrix.md),
[threat model](docs/threat-model.md),
[cryptography](docs/cryptography.md), [performance](docs/performance.md).

## Security model

- **No formal proof of the whole system.** The cryptographic building
  blocks (CKKS, BinFHE, BGV, Ed25519, HPKE, secure aggregation, the
  discrete Gaussian) have published analyses. Their composition in
  Encompute has none. The assurance suite tests 159 security invariants
  (150 in 0.3; the rest cover the public-sector governance work below)
  with positive, negative, adversarial and end-to-end evidence. A passing
  report means those invariants held for the tested cases. It does not
  prove the system secure.
- **Trust reports judge authorization expiry at verification time.** An
  owner's authorization with an expiry verifies only while it has not
  expired, so a report on a job that ran while the authorization was valid
  fails once it has expired. A bundle carries no signed execution time to
  judge it against; evaluating validity at execution time is planned. An
  authorization without a purpose or policy applies to every purpose or
  policy, and authorizations name no project.
- **An independent security review of 0.3.0-rc.3 has reported.** Its
  55 findings, 7 more from a later review of their fixes
  (ENC-SF-2026-033 to 094), and the fixes are listed in
  [docs/security-findings.md](docs/security-findings.md). Some are only
  partly fixed; the remainders are listed below and in that page's
  "Open" list.
- **Receipts are signed claims, not proofs.** An evaluator signs what it
  says it computed. A dishonest evaluator can sign a wrong result, and the
  receipt still verifies. Only verified execution rules this out, and it
  is research only.
- **Verified execution is research only.** It needs the `vfhe-research`
  build, covers only `u8`, `u16` and `bool` with `+ - *`, constants and
  `& | ^ ~` on BGV, and is sound but not succinct: the client redoes the
  whole computation to verify it. There is no proof for CKKS or BinFHE
  programs.
- **The evaluator is trusted to be honest-but-curious.** Malicious
  evaluators (outside verified execution), malicious clients and colluding
  parties are out of scope for FHE execution.
- **CKKS is not IND-CPA-D secure.** Never return decrypted CKKS results to
  the evaluator. Encompute adds no noise flooding. The same rule applies
  to exact programs, whose decryption failure probability is small but not
  zero.
- **The evaluator sees program structure.** Operations, public constants
  and weights, shapes, declared input ranges, timing and ciphertext sizes
  are visible to it by design. Encrypted model weights are not supported.
- **Envelope checksums are unkeyed SHA-256.** They detect corruption, not
  tampering: an attacker can recompute them. Integrity against an attacker
  comes from the receipts and from the program, parameter and key
  bindings, not from the checksum.
- **The BinFHE key ID is a random 16-byte label,** chosen at key
  generation. It is not a commitment to the keys: it tells keys apart, it
  does not prove which keys were used.
- **The BinFHE security labels are declared, not measured.** "128-bit" and
  "2^-135 per gate" for `BINFHE_STD128_GINX_BITS_V1` are the values
  OpenFHE states for its STD128 parameter set. Encompute did not measure
  them independently. CKKS parameters are checked against the HE Standard
  128-bit table; BinFHE parameters are taken from OpenFHE.
- **The evaluator binary links all of OpenFHE.** It statically links
  OpenFHE, including OpenFHE's own key-generation and decryption routines.
  It contains no Encompute key-generation, encryption or decryption code,
  and it never receives a secret key, so it cannot decrypt.
- **The client's secret key is stored unencrypted.** `secret.key` is
  written with file mode 0600 and no other protection. Protect it with
  disk encryption, or keep the key directory in a key store.
- **Local mode shares one process.** Without `--remote`, client and
  evaluator run in one process: anyone who compromises it sees both.
- **The evaluator speaks plain HTTP.** Put a TLS proxy in front of it.
- **No FHE key rotation and no threshold decryption.** One client holds
  each secret key.
- **Client side channels are out of scope,** and so are timing side
  channels of DP noise sampling.

## Encrypted computation

- **Exact FHE is slow.** Every AND, OR and XOR on OpenFHE exact is a
  bootstrapped gate of 54 to 62 ms on one core (Apple M3 Max, measured
  several times). The eligibility rule of example 19 needs 381 gates:
  31.1 s on one worker, 7.8 s on 8. The slowest corpus programs take
  69.6 s on one worker and 27.6 s on 8. An 8-bit addition costs 34 gates,
  a 32-bit multiplication 2,824 gates. Source:
  [docs/benchmarks.md](docs/benchmarks.md).
- **Exact evaluation keys are large.** About 525 MiB of BinFHE evaluation
  keys per client (bootstrapping and key switching), generated in about
  4.5 to 7 s and uploaded once per evaluator. Ciphertexts are 4.4 KiB per
  bit (141 KiB for a `u32`).
- **Exact programs support a fixed operation subset.** Integers `u8`–`u64`
  and `i8`–`i64`, and `bool`: `+ - *`, comparisons, `& | ^ ~`, shifts,
  `//` and `%` by public constants, `select`, `minimum`, `maximum`,
  `lookup` with tables up to 256 entries, and `cast`. No division by a
  secret, no secret indexing or loops, no floating point. Exact values at
  the API are integers within ±2^53. Anything else is refused at compile
  time.
- **BGV is used only for a narrow subset.** Programs whose operations are
  all `u8`, `u16` or `bool` additions, subtractions, multiplications,
  constants and Boolean logic may run on BGV. One operation outside the
  subset keeps the whole program on BinFHE.
- **One scheme per program.** Approximate (CKKS) and exact values cannot
  be mixed in one program, and BGV and BinFHE are never mixed within one
  program. Split the computation.
- **CKKS bootstrapping is not implemented.** A CKKS program's
  multiplicative depth is bounded by the largest 128-bit parameter set
  (N = 2^16); deeper programs are refused (ENC1201).
- **CKKS results are approximate** within the declared precision, and only
  for inputs within the declared ranges. The client checks ranges before
  encrypting; the evaluator cannot check them.
- **Functional bootstrapping is not used.** It was measured and was slower
  than Boolean gates on OpenFHE 1.5.1.
- **TFHE-rs is research only.** It is behind the off-by-default
  `research-tfhe-rs` feature, for research and differential testing. Zama
  requires a patent license for commercial use of TFHE-rs. Production
  builds refuse it (ENC1501 BACKEND UNAVAILABLE), and
  `scripts/audit-commercial-build.sh` checks that none of it is linked.

## Scale and deployment

- **Evaluators are single-node.** One job runs on one machine. Worker
  processes (`--workers N`) and parallel gates use the cores of that
  machine only. The control plane can schedule jobs across several
  evaluators, but there is no multi-machine execution of one job.
- **No high availability.** The Docker Compose deployment runs one
  control plane, one evaluator and one key broker. Migrations lock across
  control-plane replicas, but replicated control planes are not
  documented or tested.
- **The Compose OpenBao runs in development mode, in memory.** It stands
  in for a customer KMS in trials: its root keys disappear when it
  restarts, and its root token comes from `init.sh`. Point the key broker
  at your own OpenBao or Vault (over HTTPS) for real keys.
- **No built-in TLS.** No Encompute service terminates TLS, and the Compose
  deployment provides none. The control plane connects to PostgreSQL
  without TLS. Terminate TLS in front of every service and keep the
  database on a private network.
- **The newest audit events are only hash-chained.** Events after the last
  signed checkpoint (every 100 events by default) are covered by an
  unkeyed hash chain until the next checkpoint.
- **IDs can reveal existence through conflicts.** Other tenants' resources
  are "not found", but registering an ID that is already taken fails with
  a conflict. Project invitations answer the same whether the organization
  exists, but `create_user` still answers 409 for an identity that is
  already registered.
- **Identity providers are not bound per organization.** Any configured
  issuer's identity can be registered by any organization's admin, so an
  identity another organization will onboard can be registered first.
- **`/metrics` is closed in production.** It needs
  `Authorization: Bearer <metrics token>` (`ENCOMPUTE_METRICS_TOKEN_FILE`),
  unless `ENCOMPUTE_METRICS_PUBLIC=true`. Scrapers set up for rc.3 need
  the token.
- **One control-plane process per state anchor.** A lost compare-and-set
  reloads and retries, but replicas sharing one anchor are not supported.
  The anchor is rewritten on each update (it is constant in size: a few
  hundred bytes).
- **A job's sources are declarations, not data.** The control plane never
  sees inputs, so it cannot tell which data a client actually encrypts. It
  derives a job's sources from what its program declares: the purpose, and
  the registered assets its secret inputs are bound to by asset ID. The
  request's `source_assets` must list exactly those assets (none for a
  program that binds none); lineage, revocation, the audit trail and the
  trust report follow the derived set. The program's own `asset`
  declarations (owners, readers, purposes) are the submitter's text and
  are not compared with the registry; only the IDs are. Checking that a
  registered asset ID names a real asset also tells a submitter who
  already knows an ID that it exists.
- **The governance log and its mirror grow without bound.** The state
  anchor is constant in size, but every security-negative transition and
  every privacy spend is an event of the governance log (about 300 bytes),
  kept in the database and mirrored into the anchor store; nothing is
  pruned below the anchored head. 10 million spends are about 3 GB of
  mirror, and the start check, which recomputes the whole log (about 1.6
  seconds for 100,000 events), grows with it. A spend adds one append and
  one checkpoint to its latency (concurrent spends share a checkpoint),
  and still re-loads and re-verifies the whole ledger to checkpoint it
  (besides verifying it inside the spend), so its cost grows with the
  ledger's age. Size the anchor store for the mirror (the vault's entry
  limit applies to each segment, which is at most 256 KiB, not to the
  mirror as a whole). Compacting the mirror and snapshotting the log's
  frontier for startup are not built.
- **An anchor restored from the same backup forgets later spend.** When
  the database and the anchor are restored together, privacy spend rolls
  back to the backup. Keep the anchor outside the backup set, in the
  customer's vault.
- **The evaluator program table has no eviction.** Uploaded programs stay
  in memory until the evaluator restarts.
- **Trust Graph queries are quadratic** in the number of records.
- **The control plane bounds privacy reservations, but does not recompute
  them, except for a governed job's.** A reservation against an asset
  whose declared sensitivity is below what its own noise implies is
  refused, but its noise multiplier and sampling rate are the
  coordinator's declaration. A governed job's release is different: the
  control plane computes it from the job's program (sensitivity, noise and
  mechanism), reserves it itself when the job starts, and refuses a
  coordinator's report that differs.
- **Privacy scopes and populations bound what the platform records, not
  what a coordinator releases.** The release is made off the platform by a
  SecAgg coordinator: the control plane reserves the job's cost before the
  job runs and refuses one that no scope or population can pay for, but a
  coordinator that releases without reporting is stopped only by what the
  parties check themselves (a coordinator's attestation bound to the plan,
  and the privacy receipts naming the scope and population ledgers). The
  noise is central: the coordinator sees the sum before noise.
- **A scope's `max_sources_per_unit` is the owners' claim.** The
  sensitivity is multiplied by the number of sources one privacy unit may
  appear in; the control plane does not know how many agencies a person
  is registered with. Undeclared, a scoped release assumes every
  participant, which is safe and can waste budget. A person in more
  sources than declared is charged too little: the declaration is part of
  the program every owner authorizes. Across populations the same person
  is charged in each (that is the multiplication), so budgets of
  different agencies still do not compose against one another.
- **A population's cap is allocated once.** It is never raised, lowered or
  closed, and there is no way to withdraw a proposed scope (a mistaken
  proposal stays proposed; propose another with the right cap). Raising a
  cap needs a new series.
- **Recovery cannot rebuild a population or scope whose rows the database
  lost.** A missing ledger is refused at start and a frozen one stays
  frozen; but `recover` re-creates a frozen placeholder only for an asset's
  ledger, so a lost population or scope needs its rows restored from a
  backup that holds them (the governance log's checkpoint still refuses
  every older state).
- **A key broker without a generation mark can be rolled back to an older
  authenticated copy.** The state file is authenticated under a key derived
  from the KEK, so an edited file does not open. A governed production
  broker must also keep a generation mark in the organization's KMS
  (`--generation-mark openbao`); it then refuses an older copy, or a forked
  one, and grants nothing while the mark is unreachable. A standard broker
  may run without a mark: there an older copy that was genuinely
  authenticated still opens, and restoring it brings revoked keys back, so
  rollback is guarded by procedure only. The first start under a mark
  trusts the state file it finds, unless the operator passes the expected
  generation and MAC (`--expect-generation`, `--expect-state-mac`).
  Revocation does not crypto-shred: an old state file plus the unchanged
  KEK still yields the revoked keys. Keep broker backups access-controlled.
- **Evaluator upload grants are reusable** until they expire, and are not
  bound to a client.
- **A co-tenant can block a victim's evaluation-key upload.** A client that
  knows another client's key tag (it is in every ciphertext) can upload
  keys under it first; the victim's upload is then refused until that
  entry is evicted. The victim never gets a wrong result.
- **Secrets have environment-variable fallbacks.** `*_FILE` is preferred,
  but production mode also accepts the plain variable (for example
  `ENCOMPUTE_DATABASE_URL`, `BAO_TOKEN`).
- **The CLI's SecAgg coordinator reports to the control plane directly,**
  without an outbox: if the control plane is unreachable, its privacy
  events are not retried later.
- **Only OpenBao and Vault Transit** are supported root-key providers.
  OpenBao 2.1.0 is tested in CI; Vault uses the same API but is not tested
  against Vault itself. There is no AWS, GCP or Azure KMS adapter.
- **No Kubernetes, Helm or message-broker adapter yet.** HTTP delivery
  with an outbox is the only message transport.
- **Evaluator machine profiles are self-reported.** They steer scheduling
  estimates only, never a security decision.
- **The scheduler's gate estimate is a constant.** It uses 55 ms per gate
  for every evaluator, whatever its hardware.
- **Platforms.** Supported: Linux x86_64 and macOS arm64. Linux arm64 is
  experimental. macOS x86_64 and Windows are not supported.
- **macOS loads two OpenMP runtimes** when OpenFHE and torch run in one
  process.
- **The Linux wheel may bundle libgomp**, which THIRD_PARTY_NOTICES does
  not list. (Not yet checked against a built Linux wheel.)
- **Benchmarks come from one machine type** (Apple M3 Max). Linux servers
  and real TEEs have not been benchmarked.

## Attestation and TEEs

- **Only Google Confidential Space** (Intel TDX) is implemented, and the
  live GCP run has not been done yet: it is rehearsed locally and in CI
  with a simulated launcher and a test JWKS. No AWS Nitro, Azure, AMD
  SEV-SNP or GPU TEE provider exists.
- **The mock attestation provider protects nothing.** It signs whatever it
  is told. Production policies and brokers refuse its evidence.
- **Attestation trusts the TEE vendor** and its attestation service (for
  Confidential Space: Google's verifier and launcher), and the reviewed
  image: the image digest is the measurement.
- **Several key brokers per training job need a per-asset binding.** A
  training spec without `asset_brokers` still names exactly one key broker:
  a workload would trust every broker the spec names for every asset, so
  with several, one broker could grant a key of its own choosing for an
  asset another owner's broker holds (a participant's contribution key
  among them). With `asset_brokers`, a spec may name several brokers: each
  key is bound to one broker, and a workload accepts that key's grant only
  from that broker, under its pinned grant-signing key. The spec also says
  whose each broker is (`broker_organizations`): a participant's dataset
  and contribution keys go to its own broker, or, if it runs none, to the
  model owner's; never to another participant's. Two limits remain. Who
  runs a broker is the spec's word, which each participant checks before
  approving the spec (in a sovereign project the control plane also checks
  each source's owner broker when it plans). And the local `finetune` run
  holds every key at the model owner's broker, so there its binding names
  that one broker.

## Differential privacy

- **Central DP.** The SecAgg coordinator sees the aggregate before noise
  and is trusted to add the noise, as far as its attestation (bound to the
  privacy policy) goes. A coordinator that is not attested is trusted
  outright.
- **The privacy unit is what the data owner declares.** Patient-level
  guarantees hold only if `unit_ids` really identify patients, and every
  record of a patient carries the same ID. Encompute checks consistency,
  not truth.
- **A patient-level budget without DP-SGD pays for an organization's
  sensitivity.** Aggregated without Poisson sampling, nothing clips one
  patient (record, user, device) inside a party's contribution, so each is
  charged `2 × clip_norm`. The named levels compensate with twice their
  listed noise for such units (`strong`: noise 12, not 6), which keeps the
  budget's release count but also doubles the noise on the aggregate.
  Per-unit clipping (DP-SGD) needs half that noise.
- **Budgets cover releases through Encompute only.** Anything an owner
  releases about the same data elsewhere is not in the ledger.
- **Organization-level DP protects organizations, not individuals.** A
  hospital's whole update is the unit. Use patient-level DP-SGD
  (`privacy="strong-patient"`) to protect individual patients.
- **DP bounds what the released aggregate reveals** within (ε, δ). It
  does not hide the model architecture, the number of rounds or the
  training configuration, which are shared as metadata.
- **A DP plan with no budgeted asset produces no privacy receipt**, so an
  aggregation receipt has nothing to bind.
- **Randomness must be production randomness.** The deterministic noise
  feature exists for tests only and is refused in releases (ENC2204).
- **A person held by several parties is protected at group level.** The
  unit is one patient (or record, user, device) inside one party. A
  patient whose records k hospitals hold can move the aggregate up to k
  times the per-unit sensitivity (about k²ρ under zCDP). Encompute cannot
  link units across parties: set budgets with this in mind, or
  de-duplicate patients across parties before training.
- **An owner-approved unit count is public.** A DP-SGD training spec
  publishes no count derived from the data: the sampling rate is set
  explicitly or derived from a number of privacy units each owner approves
  for publication (`public_units`). That figure, if given, is released by
  the owner's consent, outside the differential-privacy guarantee. Dataset
  and grouping digests are salted commitments whose salt stays with the
  owner.
- **Secure aggregation does not guarantee a correct aggregate.** A
  malicious coordinator can abort a round or report a wrong aggregate. It
  cannot learn an honest party's input while it colludes with no more
  parties than the declared bound. Parties sign their messages; the
  coordinator's broadcasts are not signed.

## Confidential AI

- **PyTorch runs in plaintext inside the TEE.** Fine-tuning is protected
  by attestation, secure aggregation and DP, not by FHE. The TEE protects
  data in use.
- **Hugging Face support is narrow.** Only sequence classification, and
  only BERT and DistilBERT are tested end to end. RoBERTa is accepted but
  not tested end to end. Everything else is refused (ENC2504): decoder-only
  language models (GPT, Llama, Mistral and similar), text generation, token
  classification, question answering, vision and multimodal models, remote
  code (`trust_remote_code`, `auto_map`) and pickled weights.
- **Library versions are pinned per model package.** A package binds the
  major.minor versions of Transformers, PEFT and PyTorch it was imported
  with. Other versions are refused; re-import the model to move.
- **Only small models have been measured,** on CPU. GPU training,
  quantization and multi-GPU training are not tested or supported.
- **LoRA only.** Full fine-tuning and other adapter methods are not
  supported.
- **Local revocation checks are run by the beneficiary.** In local
  `finetune` runs the revocation checks for resume, inference and export
  read the model owner's trust bundle plus any owner-supplied bundles
  (`revocations=`); the model owner benefits from forgetting a revocation,
  so enforcement relies on owners revoking at their key brokers or control
  plane. In these checks a revocation of a parent asset that the trust
  report does not honour (signed by a non-owner, with an invalid
  signature, or revoking a single authorization) also refuses, so anyone
  whose bundle is passed in can stop the run until it is resolved; the
  trust report itself still honours only the owner's revocation.
- **The training image ships PyTorch 2.3 and Transformers 4.46, which
  have open CVEs.** The release's vulnerability gate scans the TEE images
  like every other image; these findings pass only through exceptions for
  the exact advisory, package and installed version, each with the
  analysis that the code is unreachable, the controls that keep it so, an
  upstream tracking link and an expiry (`security/exceptions.toml`). They
  expire on 2026-12-31, which forces the upgrade planned for 0.4.
- **The plan validator is only partly independent.** It recomputes the
  program's semantics and applies its own floor of core requirements, but
  its exact-equality check still uses the planner's own derivation.

## Public-sector governance (not part of 0.3)

Governed projects are being built after 0.3 (see
[docs/public-sector.md](docs/public-sector.md)). What exists so far has
these limits:

- **`source_revoked_at` is not erasure.** Revoking a source marks the
  derived results downstream and blocks their new use, derivation and
  export; it does not recall or delete anything already released. Copies
  recipients hold, and results exported before the revocation, stay
  where they are; the control plane records the later revocation and
  never claims otherwise. Only derived results recorded through
  `POST /v1/jobs/{id}/derived-assets` are marked; an asset registered
  with parents by other means is not (every governed use walks its
  ancestors all the same).
- **Export keys are the custodian's word.** The custodian's signed
  release record names each recipient's export key; neither the control
  plane nor the broker can check that the key belongs to that
  organization. A custodian that names a wrong key exports to whoever
  holds it.
- **An owner's `max_releases` counts exports separately from key
  releases.** The control plane counts exports of results released under
  an authorization, and jobs reading them, through every derivation hop.
  Each key broker counts the releases and exports it makes itself: a
  lineage owner's authorization installed at a custodian's broker is
  counted there, separately from its own broker's count.
- **Lineage owners share their governance key with custodians.** A
  custodian's broker releases or exports a derived result's key only with
  an authorization of every organization whose data it derives from,
  verified under that organization's governance key, which the
  custodian's owner pins at its broker from the control plane's signed
  attestation of it (`encompute keys governance-key pin-lineage`), and
  each lineage owner must install its authorization there. A lineage
  owner's revocation reaches a custodian's broker from the control plane
  once anchored (deny-only), or directly as a signed revocation; the
  control plane stops issuing tickets at once. A rotated lineage owner's
  key is pinned again from a newer attestation; results bound under the
  old key ID are then neither released nor exported until the custodian
  has the control plane's co-signature re-issued
  (`POST /v1/assets/{id}/release-cosignature`) and re-binds the key
  (`encompute keys rebind-lineage`). A pinned lineage key is relied on
  only while its attestation is younger than the broker's maximum age
  (24 hours by default): a key revoked at the control plane stays usable
  at a custodian's broker for up to that long unless the revocation is
  attested there sooner, and a broker whose owner does not re-attest stops
  releasing derived results after it.
- **Retention blocks use; it does not delete data.** Once a dataset
  version's `delete_after` passes, Encompute expires it, blocks every
  further use of it and of what was derived from it, tells its key broker,
  and records all of it; deleting the data itself (and its key material,
  where the owner's KMS keeps it) is the owner's storage's job, and
  Encompute never claims it happened. Results released or exported
  before the deletion date stay where they are. Expiry runs in the
  background every few seconds, so a version may be expired a little
  after its deletion date; every check also compares the deletion date
  itself, so nothing uses it in between. `evidence_retention_until` is
  recorded and only ever extended, but nothing purges evidence yet: the
  control plane keeps all of it.
- **Replacing the control-plane key at a broker is the owner's word.**
  `--replace-control-key` accepts whatever other key the operator types,
  recorded in the broker's state and printed as an audit line; the broker
  cannot check that the control plane's key really changed.
- **The custodian is trusted for derived data it holds.** The custodian
  runs the broker that holds a derived result's key. Its lineage checks
  defend against a compromised control plane and a careless custodian,
  not a malicious one, which holds the key material. The control plane
  attests lineage owners' keys and co-signs release records, so a
  compromised control plane and a malicious custodian together could fake
  a lineage owner's consent; neither can alone.
- **No decryption tickets.** Tickets of kind `decrypt` are neither issued
  nor accepted; exports cover released results for now.
- **Boolean releases still leak through repeated questions.** A
  boolean-only output reveals one bit per job; a bounded category a few.
  Probing limits bound this channel, they do not eliminate it: an
  authorization whose ceiling admits boolean-only releases must set
  `max_executions` and `max_releases`, and one job releases at most
  `max_outputs_per_job` boolean-only outputs per source (one by default).
  Within those limits, well-chosen questions about the same records still
  add up. Statistics over records belong in the differential-privacy
  classes, which account for what repeated releases reveal.
- **Output forms are what the compiler can show.** A bounded category
  rests on the integer range analysis; a boolean on the output's type.
  Neither says what the bit means: owners approve the program itself.
- **Four eyes assume one identity per person.** Quorums count distinct
  user identities (identity provider issuer and subject). If one person
  holds two identities, in one identity provider or two, the control plane
  counts two people. Giving each person one identity is an onboarding
  control of the organization's identity provider, outside Encompute.
- **Role combinations with auditor are not yet removed everywhere.**
  Auditor separation is enforced in organizations taking part in governed
  projects. Elsewhere, and for combinations made before (bootstrap admins
  hold admin, operator and auditor in the platform organization), they
  remain; `GET /v1/security/legacy-service-admins` lists them
  (`auditor_combinations`) and a later migration removes them. Such an
  auditor stays read-only in governed projects.
- **Auditor organizations read no privacy ledgers yet.** A ledger is its
  asset owner's until privacy scopes give a project its own ledger.
- **Declared placement is refused.** A governed broker releases no key
  for an execution that declares placement until attested placement can
  be checked.
- **A compromised control plane can still deny and delay.** It cannot
  release a key without an owner-signed authorization installed at the
  owner's broker, but it can withhold tickets and delay revocation
  messages. The owner's local revocation at its broker does not depend on
  it.
- **The ticket's anchor counter is carried but not yet checked** by
  brokers.
- **Governed releases are serialized** at a broker with a generation mark:
  each one waits for the compare-and-set in the organization's KMS.
- **The generation mark needs a KMS write permission** scoped to one KV-v2
  path, in addition to Transit. Revoking an authorization offline, and
  binding a key to a source version, are operator acts on the broker.
- **Standard key brokers may run without a generation mark** (see "A key
  broker without a generation mark" above).

## Compatibility and upgrades

- **Every format reader accepts exactly one version.** There is no
  artifact migration tool yet (`encompute migrate` is planned). A compiler
  change can require recompiling `.encompute` artifacts, and clients and
  evaluators must run the same Encompute minor release. See
  [docs/compatibility.md](docs/compatibility.md).
- **Database migrations are forward only.** To downgrade, restore a backup
  taken before the upgrade.
- **Legacy service accounts with `security_admin` are accepted in 0.3.x.**
  A service account given `security_admin` before 0.3.0 keeps it (for
  disabling, revoking and audit reads); it is never stripped silently. It
  never counts as a policy's proposer or approver. The control plane
  warns on every start (log line, audit event,
  `encompute_legacy_service_admins` gauge), and
  `encompute security legacy-service-admins` lists them (exit 1). 0.4.0
  will refuse them, at startup or through a migration announced in
  advance. See "Upgrading from 0.3.0-rc.3 or earlier" in
  [docs/deployment.md](docs/deployment.md).
- **Python 3.11 or later** is required. CI tests 3.11 and 3.12.
