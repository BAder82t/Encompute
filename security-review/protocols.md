# Encompute protocols

This page describes each protocol message a reviewer needs to check: what
it contains, who signs it, what the recipient verifies, and where the code
is. Mechanisms and parameters are in
[docs/cryptography.md](../docs/cryptography.md). Adversaries are in
[docs/threat-model.md](../docs/threat-model.md).

Conventions used throughout:

- `tagged(domain, bytes)` = `SHA256(domain || 0x00 || bytes)`
  (`crates/encompute-verification/src/hash.rs`). SecAgg's variant
  length-prefixes each part (`crates/encompute-secagg/src/crypto.rs`).
- "Canonical JSON" = keys sorted by UTF-8 bytes, no whitespace, integers
  only; floats are refused (`crates/encompute-verification/src/canonical.rs`).
- A signature is Ed25519 over the 32-byte `tagged` digest of the canonical
  JSON, never over raw JSON.
- All services speak plain HTTP (`tiny_http`). TLS is the deployment's job.

## 1. Envelopes (client ↔ evaluator)

Source: `crates/encompute-protocol/src/lib.rs`,
`crates/encompute-openfhe-exact/src/lib.rs`.

**`ENCM` envelope** (every object between client and evaluator, and on
disk):

```text
"ENCM" | format u16 LE (=1) | header_len u32 LE | header (JSON) | payload | SHA-256(all before)
header = { kind, scheme, backend, backend_version, parameter_set_id,
           program_id?, key_id?, items: [{name, len}] }
kind   = evaluation_keys | inputs | outputs | secret_key
```

- `parameter_set_id`: SHA-256 of the artifact's `parameters.json`.
- `program_id`: SHA-256 of `program.eir`.
- `key_id`: SHA-256 of the evaluation-key payload (CKKS, BGV).
- The reader passes an `Expect` and every field must match
  (`Envelope::check`). The header is at most 1 MiB; item lengths must sum
  to the payload length.

**`ENCBINF1` envelope** (each BinFHE object, nested inside `ENCM`):

```text
"ENCBINF1" | version u32 (=1) | backend name | parameter_id[32] | key_id[16]
| kind u8 (1 ciphertext, 2 evaluation keys, 3 secret key) | elem u8
| count u32 | (len u64, payload)* | SHA-256(all before)
```

- `key_id` is 16 random bytes chosen at key generation. It is a label,
  not a commitment to the key.
- Limits: payload ≤ 1 GiB, count ≤ 65 536, backend name ≤ 64 bytes.

**What an envelope does not do:** the trailing SHA-256 is unkeyed. It
detects corruption, not an attacker, who can recompute it. Authenticity of
results comes from receipts (section 2).

## 2. Execution receipts and proofs

Source: `crates/encompute-verification/src/{spec,receipt,verify,proof}.rs`,
`crates/encompute-runtime/src/client.rs`, `crates/encompute-cli/src/main.rs`
(`verify`).

**Execution spec** (the statement of what runs):
`{version, program_id, plan_id, parameter_set_id, plan_kind, plan_version,
semantics, scheme, backend, backend_version, policy_id?, privacy_policy_id?}`.
`ExecutionSpecId = tagged("encompute.execution-spec.v1", canonical spec)`.
The evaluator builds the spec from its own compilation of the program; it
does not trust the client's plan (`crates/encompute-evaluator/src/session.rs`).

**Receipt** (version 3):

```text
ExecutionReceipt = { version, execution_id (random UUIDv4), spec_id, program_id,
  plan_id, parameter_set_id, key_id, request_commitment, output_commitment,
  scheme, backend, backend_version, transcript_hash?, evaluator_id,
  evidence (none | vfhe{relation, verification_key_id, proof_digest}),
  attestation? {attestation_id, workload_session_id} }
request_commitment = tagged("encompute.execution-request.v1", request envelope bytes)
output_commitment  = tagged("encompute.execution-output.v1",  response envelope bytes)
evaluator_id       = tagged("encompute.evaluator.v1", evaluator public key)
signature          = Ed25519(tagged("encompute.execution-receipt.v1", canonical receipt))
wire form          = canonical JSON {receipt, evaluator_public_key, signature}, ≤ 16 KiB
```

**Client verification** before decrypting (`verify_receipt`): the
signature with `verify_strict` against the **trusted** key; then spec ID,
program, plan, parameter set, key ID, both commitments, scheme, backend,
backend version, the evidence kind, and the transcript hash, each against
the client's own values.

**Evaluator key trust:**

- Direct remote run (`run --remote`): `--trust-evaluator`, else
  `evaluator.pub` in the key directory, else the key announced by
  `GET /v1/info`, pinned on first use.
- Jobs a control plane schedules (CLI `jobs run`, the Python SDK, the
  native SDK): the control plane names the evaluator and its receipt key;
  the client accepts that key only if it is in the client's own pin set
  (`--trust-evaluator`, `ENCOMPUTE_TRUSTED_EVALUATORS`,
  `trusted_evaluators=`). The check runs before anything is sent to the
  evaluator. A key outside the set is refused (ENC2607); an empty set
  refuses every key; no pin refuses the job (ENC2605) unless the
  development opt-out is given, which `ENCOMPUTE_ENV=production` refuses
  (`crates/encompute-runtime/src/remote.rs` `trusted_evaluators`,
  `check_trusted_evaluator`; `python/encompute/client.py`
  `check_evaluator`).
- For exact programs, the client also refuses a decrypted output outside
  the interval range analysis proves for it
  (`crates/encompute-runtime/src/client.rs`).

**`encompute verify` exit codes:** 0 when every binding it can check was
checked, 3 when the signature is valid but some bindings were not checked
(for example no `--trust-evaluator`), 1 when a check fails, 2 for usage or
input errors. It does not compare the receipt's `evidence` kind, and it
binds `key_id` only when `--request` is given.

**A receipt is a signed claim, not a proof.** It makes the evaluator's
statement attributable and non-transferable. An evaluator can sign a
fabricated result.

**Semantic transcript** (exact programs): the canonical operation list with
no runtime values, bound to the spec ID;
`TranscriptId = tagged("encompute.execution-transcript.v1", canonical transcript)`.

**Re-execution proof** (research, `vfhe-research`, BGV subset): an
`ENCP` object whose header binds relation `reexecution-v1`, the spec,
transcript, both commitments and
`verification_key_id = tagged("encompute.verification-key.v1", "reexecution-v1" 0 plan_id 0 key_id)`.
The verifier recompiles the plan, checks the transcript, loads the client's
own evaluation keys, re-evaluates, and requires every output ciphertext to
match byte for byte (`crates/encompute-vfhe/src/lib.rs`). No match, no
decryption (`decrypt_proven`).

## 3. Service identities and signed requests

Source: `crates/encompute-verification/src/service.rs`,
`crates/encompute-control/src/authn.rs`.

Each service (control plane, evaluator, key broker, SecAgg coordinator,
automation) has an Ed25519 key. Service IDs are 1-63 characters of
`[a-z0-9-]`.

```text
headers:   Encompute-Sender, -Recipient, -Timestamp, -Nonce, -Bind, -Signature
statement: { method, path, sender, recipient, timestamp, nonce (16 random bytes, hex),
             bind (map of related IDs), body_sha256 }
signature: Ed25519(tagged("encompute.service-request.v1", canonical statement))
```

Recipient checks (`ServiceHeaders::verify`): recipient is me;
|timestamp − now| ≤ 300 s; nonce well formed; no query parameter named
twice; signature valid. The control plane also looks up the sender's
active service account and its public key in the database, and stores the
nonce in `request_nonces` (primary key `(sender, nonce)`) until
`max(now, timestamp) + 300 s + 60 s` by its own clock, which also prunes
it; a second use is refused.

Notes:

- `path` is the URL path with its query parameters sorted into a canonical
  form (unchanged when there is no query). Because `?a=1&a=2` and
  `?a=2&a=1` sign alike but may parse differently, a target that repeats a
  parameter is refused even when signed (`repeats_a_query_parameter`).
- `bind` is informational. Recipients authorize from the method, path,
  body and the authenticated sender, never from `bind`.
- Service accounts are registered by an `organization_admin`; evaluator and
  SecAgg accounts only in the platform organization. A service account
  cannot hold `security_admin`. An organization's key broker account
  cannot take an ID that another organization's assets name as their
  broker. There is no key rotation endpoint; an account can be disabled,
  and the disable is recorded in the state anchor (section 9).

## 4. Asynchronous messages

Source: `service.rs` (`seal`, `open`), `crates/encompute-control/src/transport.rs`,
`ops/jobs.rs` (`receive_message`).

```text
MessageEnvelope = { protocol_version (=1), message_id ("msg_" + 16 random bytes),
  kind, sender, recipient, organization?, project?, job?, round?,
  created_at, expires_at, payload_digest = SHA-256(canonical payload), payload,
  signature = Ed25519(tagged("encompute.service-message.v1", all fields but payload)) }
```

- Inline payloads are at most 64 KiB.
- `open` checks the version, recipient, expiry, `created_at ≤ now + 300`,
  the digest and the signature.
- Delivery: the control plane's outbox retries at least once (batches of
  20, up to 100 attempts), POSTing to `{url}/v1/messages` as a signed
  request. Consumers deduplicate by `message_id` in an `inbox` table and
  apply idempotent effects.
- Kinds the control plane accepts: `job.completed`, `evaluator.heartbeat`,
  `privacy.event`, `key.release` (key brokers only, about assets of their
  own organization; the platform's brokers about any),
  `secagg.round.completed`.
- Kind the key broker accepts: `asset.revoked`, from the pinned
  control-plane key only. The outbox sends it only once the revocation is
  recorded in the state anchor.

## 5. Job grants and consent to start

Source: `service.rs` (`JobGrant`), `crates/encompute-control/src/ops/jobs.rs`
(`schedule_job`, `start_job`), `crates/encompute-evaluator/src/control.rs`.

```text
JobGrant = { version (=1), job_id, organization, project, plan_id, spec_id, program_id,
  evaluator, backend, profile, issued_at, expires_at (issued_at + 3600),
  issuer, issuer_public_key,
  signature = Ed25519(tagged("encompute.job-grant.v1", canonical grant with signature "")) }
header:   Encompute-Job-Grant: hex(JSON grant)
```

1. The control plane schedules a queued job onto a ready evaluator whose
   registered backend and profile fit, and signs the grant.
2. The client sends the grant with its job request to the evaluator.
3. The evaluator verifies the grant (`JobGrant::verify`): version;
   `issuer_public_key` equals the pinned `ENCOMPUTE_CONTROL_PUBLIC_KEY`;
   signature; `evaluator` is itself; `program_id` matches; not expired. It
   refuses a job ID it has already used (in memory).
4. The evaluator asks the control plane to start the job with a signed
   `POST /v1/jobs/{id}/start`. The control plane starts it only if the
   caller is the scheduled evaluator, the job is still `queued`, the grant
   has not expired, and no source asset is revoked.
5. The evaluator runs, returns the receipt to the client, and reports
   `job.completed`. The control plane rebuilds the trust report from the
   grant, receipt, commitments and plan on every request.

`JobGrant::verify` does not itself compare `spec_id`, `backend` or
`profile` with anything; they are covered by the signature.

With a control plane, the evaluator also needs a grant naming the program
for a program upload (checked before anything is compiled or loaded), a
key upload and a key lookup, and `GET /v1/info` lists only the program a presented
grant names (`crates/encompute-evaluator/src/server.rs`). The control
plane returns the evaluator's URL and receipt key only to the submitting
organization.

## 6. Attested key release

Source: `crates/encompute-keybroker/src/{lib,server,workload,client,store,root}.rs`,
`crates/encompute-attestation/src/{binding,grant,gcp,policy,provider}.rs`.

```text
Workload                                   Key broker (owner)
  POST /v1/challenge  ───────────────────▶  nonce (32 random bytes), expires in 300 s,
                                            single use, ≤ 4096 open
  session key: X25519 generated in the TEE
  binding = { version, execution_spec_id, policy_id?, artifact_digest,
              evaluator_public_key (Ed25519), session_public_key (X25519),
              challenge_nonce, privacy_policy_id? }
  binding_hash = tagged("encompute.workload-binding.v1", canonical binding)
  attestation token with eat_nonce = binding_hash
  POST /v1/attest {evidence} ────────────▶  consume the challenge (whatever the outcome);
                                            verify token; freshness; production mode
                                            refuses development evidence;
                                            open a session (≤ 600 s)
  POST /v1/release {session, asset} ─────▶  re-check the asset's attestation policy and its
                                            max evidence age; current key version not revoked;
                                            unwrap the key; HPKE-seal it; sign the grant
  ◀──────────── EncryptedKeyGrant {header, encapsulated_key, ciphertext, signature}
  verify the signature; check the signer against the pinned broker key;
  open with the session key; check session ID, asset and spec
```

- **Confidential Space tokens** (`gcp.rs`): RS256 only, `kid` required,
  issuer `https://confidentialcomputing.googleapis.com`, audience = the
  broker ID, `swname = CONFIDENTIAL_SPACE`, `secboot = true`, the nonce
  contains the binding hash, image digest present, `dbgstat` gives the
  debug flag, `hwmodel` gives the TEE, support attributes give the TCB
  status. With `--jwks google`, the broker refetches Google's JWKS when a
  token names an unknown `kid` (at most once a minute) and once the set
  is an hour old; a failed fetch keeps the current keys.
- **Policy check** (`AttestationPolicy::check`): development evidence only
  if allowed; TEE and image in the allowed lists; no debug unless allowed;
  TCB at least the minimum; spec, policy and privacy policy IDs equal;
  artifact digest when the policy sets one.
- **Refusals** tell the unauthenticated caller what its own evidence
  shows, never the values the policy expects (spec, policy, privacy
  policy, artifact, minimum TCB). The full reason goes to the broker's
  log (`policy.rs` `public_denial`, `server.rs`).
- **Grant** (`grant.rs`, version 2): HPKE base mode, X25519-HKDF-SHA256 /
  HKDF-SHA256 / ChaCha20-Poly1305, `info = "encompute.key-grant.v1"`,
  `aad` = canonical header `{version, broker_id, asset_id, key_version,
  policy_id, execution_spec_id, session_id, binding_hash,
  attestation_digest, expires_at, broker_public_key}`.
  `session_id = tagged("encompute.workload-session.v1", evaluator key || session key)`.
- **Grant signature:**
  `signature = Ed25519(tagged("encompute.key-grant-signature.v2",
  canonical {header, encapsulated_key, ciphertext}))`, under the broker's
  grant-signing key, whose public half is `broker_public_key` in the
  header. The workload checks it with `verify_strict` before opening the
  grant (`WorkloadSession::open`), and refuses version 1 (unsigned)
  grants. HPKE base mode does not authenticate the sender; the signature
  does, but only against a pinned key, since the header names its own
  signer.
- **Where the pin comes from** (`workload.rs` `acquire_keys`,
  `client.rs` `BrokerClient::trusting`): from the workload's attested
  identity, never from whoever supplies the broker's address. A training
  worker trusts the training spec's `key_brokers` (broker ID → hex Ed25519
  grant-signing key), which is part of the spec ID the worker attests to;
  a grant is accepted only if `key_brokers[header.broker_id]` equals
  `header.broker_public_key`. The Confidential Space FHE workload reads
  its pins (`ASSET KEY` lines) from `/app/broker-keys` in the measured
  image and passes them as `URL#KEY`; `BROKER_URLS` entries that carry a
  key are refused (`deploy/confidential-space/run-workload.sh`). With any
  attester other than the development (mock) one, an unpinned broker is
  refused. All grants of one broker session must carry the same signer.
- **The broker's HTTP API has no caller authentication** on challenge,
  attest and release. Protection comes from attestation, sealing and the
  grant signature. It is rate-limited to 60 requests per minute per source
  address and 96 KiB per body. Key protection, rotation and policies are
  offline CLI operations.
- **Revocation** arrives as a signed `asset.revoked` message from the
  pinned control plane, and replaces the stored key with `Destroyed` in the
  broker's state file. The KEK is not rotated, so an older copy of the
  state file still holds the key (no crypto-shredding).
- **Storage**: asset keys wrapped under a 32-byte KEK with
  ChaCha20-Poly1305; the KEK wrapped by OpenBao/Vault Transit under the
  organization's root key (associated data names the organization). The
  OpenBao client follows no redirects: a 3xx answer is an error, so the
  `X-Vault-Token` never goes to another origin. An existing KEK file must
  not be accessible to group or others; a token file (`BAO_TOKEN_FILE`)
  must be a regular file not writable by group or others.
- **State authentication** (`lib.rs`, `store.rs`): the state file
  (`broker.json`) carries `generation`, raised by every save, and
  `mac = HMAC-SHA256(K, "encompute.broker-state.v1\0" || JSON(state without mac))`,
  `K = HKDF-SHA256(ikm = KEK, salt = none, info = "encompute.broker-state-mac.v1")`.
  The MAC covers every other field, `generation` included: release
  policies, mode, organization, key versions, revocations, the wrapped
  grant-signing key. A state whose MAC fails does not open. A state with
  no MAC (written by 0.3.0-rc.3 or earlier) opens only through
  `encompute keys upgrade-state`, which prints what it releases to whom
  and saves it authenticated only with `--confirm`. A store that cannot
  authenticate state backs no production broker. Not detected: a rollback
  to an older state file the broker itself wrote (its MAC verifies).

## 7. Secure aggregation rounds

Source: `crates/encompute-secagg/src/{protocol,round,service}.rs`; decision
record [0012](../docs/adr/0012-secure-aggregation.md).

**Setup.** The aggregation spec (`encagg1:`) fixes the plan (program,
policy, participants, minimum, colluding bound, codec, DP settings,
privacy policy, plan ID), every party's Ed25519 key, the threshold and the
attestation policies. A round is `{spec_id, sequence, nonce, coordinator
key, opened_at}`; `round_id = tagged("encompute.aggregation-round.v1", …)`.
A party refuses a round whose sequence is not newer than the last it
joined for that aggregation spec, or above 2^53 − 1, and records the round
before contributing. `aggregate join` keeps this in its `--state` file per
spec ID, updated under an exclusive lock and replaced atomically. A spec
with any privacy-budgeted contributor must declare `dp`: every aggregate
is a release, even one declared sealed, and a budgeted party does not
join a round without DP.

| Round | Party sends (signed, bound to `round_id`) | Party checks |
|---|---|---|
| 0 Advertise | two X25519 public keys (`c` for shares, `s` for masks), attestation ID; signed contribution metadata (asset, policy, spec, codec, vector length, keys digest) | spec identical to the approved one; coordinator attestation where required |
| 1 Share keys | Shamir shares of `s` and of the self-mask seed `b` for each other party, encrypted per recipient (ChaCha20-Poly1305); commitment to `b` | every advertisement's signature; no duplicate keys; own key unaltered; at least t parties |
| 2 Masked input | `y = x + PRG(b) ± Σ PRG(KDF(DH(s_u, s_v)))` mod 2^m, with a signed commitment | survivor set ⊆ previous, contains me, at least t |
| 3 Consistency | signature on the survivor set | survivor set ⊆ previous, contains me, at least t |
| 4 Unmask | `b` shares for survivors, `s` shares for dropped parties, never both for one party | at least t signatures on the same survivor set, else "the coordinator is equivocating" |

**Finalize** (coordinator): reconstruct each `b` and check it against its
commitment; reconstruct each dropped party's `s` and check it regenerates
the advertised public key; any mismatch aborts. Then (with DP) add noise
and write the ledger (section 8), and sign the aggregation receipt:
`tagged("encompute.aggregation-receipt.v1", canonical manifest)`, where the
manifest lists the round, spec, policy, codec, threshold, eligible,
advertised, contributing and dropped parties, the signed metadata,
contributions and confirmations, attestation IDs, the aggregate commitment
and the privacy receipts.

**Limits:** threshold `t = max(minimum, ⌊(n + colluding)/2⌋ + 1)`; at most
255 parties; coordinator broadcasts are not signed; the aggregate's
correctness is not verified.

## 8. Privacy events, ledgers and receipts

Source: `crates/encompute-privacy/src/{ledger,release,accountant,rdp}.rs`,
`crates/encompute-cli/src/aggregate.rs`, `crates/encompute-control/src/ops/assets.rs`.

**File ledger** (one per asset, JSON lines, mode 0600, ≤ 64 MiB):

```text
line 1:  Genesis { version, asset_id, budget, privacy_policy_id }
line n:  Entry { seq, prev, event, hash }
event =  Reserve { event_id, policy_id, execution_spec_id, round_id, output,
                   mechanism, sensitivity, sigma2, vector_len, rng }
       | Commit  { event_id, output_commitment }
genesis_hash = tagged("encompute.privacy-ledger.v1", "genesis" || canonical genesis)
entry_hash   = tagged("encompute.privacy-ledger.v1", seq || prev || canonical event)
checkpoint   = { seq, root }
```

**Release order** (`release`): lock every parent ledger in sorted order →
check budgets → append `Reserve` (fsync) → sample noise → append `Commit`
(fsync) → sign privacy receipts. A crash after `Reserve` leaves the charge
in place; the round cannot be rerun.

**Privacy receipt:** event, asset, round, output, policy, privacy policy,
spec, unit, mechanism, sensitivity, σ², ρ and ε costs, cumulative ρ and ε,
δ, budget, output commitment, ledger position and root, RNG label; signed
by the releasing coordinator over
`tagged("encompute.privacy-receipt.v1", canonical receipt)`.

**Control plane:** after a round completes, the coordinator (when
`ENCOMPUTE_CONTROL_URL` is set) sends each ledger event of the round as a
signed `privacy.event` message. The control plane:

- checks the sender is an authorized SecAgg spender for the asset;
- locks the ledger row (`SELECT … FOR UPDATE`);
- refuses the event (ENC2202, PRIVACY STATE ROLLBACK) if the database's
  ledger no longer extends the checkpoint in the state anchor;
- treats a repeated `event_id` with identical content as already applied,
  and different content as a conflict;
- treats a ledger frozen in the database or in the anchor as exhausted
  (ENC2201);
- for a reservation, refuses (ENC2204) one whose declared sensitivity is
  below what its own mechanism and noise imply for the ledger's unit, or,
  in production, whose noise is not drawn with `csprng`;
- appends the event and an audit record in one transaction;
- updates the state anchor before it replies; the anchor refuses a
  checkpoint that does not extend the anchored one.

The control-plane charge is recorded after the release has happened. It
keeps the authoritative record and blocks later releases; it cannot undo
an earlier one. The control plane's ledger is a separate hash chain from
the coordinator's file ledger.

## 9. Audit chain and state anchor

Source: `crates/encompute-control/src/{audit,anchor,control}.rs`.

**Audit event:**
`{seq, event_id, at_us, organization, actor, action, resource_type,
resource_id, project, result, request_id, refs, prev_hash, hash}`,
`hash = SHA256("encompute.audit-event.v1\0" || canonical event with hash "")`,
genesis `prev_hash = "genesis"`. Events are appended inside the caller's
transaction, under a lock on the single `audit_head` row. `refs` values
and `resource_id` must be ≤ 256 characters of `[A-Za-z0-9-_.:/@+]`, so a
payload cannot be written into the audit trail through them. Checkpoints
are signed under `encompute.audit-checkpoint.v1`.

**State anchor:**

```text
StateAnchor = { version, counter (monotonic), audit_seq, audit_root,
                ledgers: asset → {seq, root}, frozen: [asset],
                revoked: [asset], disabled_services: [id], disabled_users: [id],
                ended_jobs: [job],
                signer, signer_public_key,
                signature = Ed25519(tagged("encompute.state-anchor.v1", …)) }
```

- `revoked`, `disabled_services`, `disabled_users` and `ended_jobs` are
  omitted while empty, so an anchor written before them still verifies;
  once present they are signed.
- Stored in a directory (`state-anchor.json`, written through a temporary
  file and rename) or in OpenBao/Vault KV v2 with check-and-set. An update
  that loses the compare-and-set reloads the stored anchor, verifies it
  and re-applies its change. One control-plane process per anchor is
  supported.
- Updated after every privacy spend, at ledger creation, at each audit
  checkpoint (every 100 events by default), and before acknowledging each
  security-negative transition: a revocation, a frozen ledger, a disabled
  service account or user, a cancelled or failed job.
- The anchor only moves forward along the same chains: it refuses a ledger
  checkpoint or audit root that does not extend the anchored one. While
  the service runs, a spend on a ledger that no longer extends the anchor
  is refused (PRIVACY STATE ROLLBACK), and an audit checkpoint over a
  chain that does not extend the anchored root is refused (AUDIT STATE
  ROLLBACK). Both raise `encompute_state_rollback_total`.
- At startup the control plane recomputes the audit chain and refuses to
  start (`STATE ROLLBACK … STARTUP REFUSED`) if the database is behind the
  anchor, if any non-frozen ledger does not extend its anchored
  checkpoint, or if the database undoes an anchored transition (FREEZE,
  REVOCATION, SERVICE ACCOUNT, USER or JOB STATE ROLLBACK). Recovery
  freezes the affected ledgers (treated as exhausted), re-freezes,
  re-revokes, re-disables and re-fails what the anchor records, records
  the gap in the audit trail, and re-signs the anchor.
- A key broker receives an `asset.revoked` message only once the anchor
  records the revocation.
- Audit events after the last anchored checkpoint are covered only by the
  unkeyed hash chain.

## 10. Trust bundles and reports

Source: `crates/encompute-trust/src/{graph,authz,report}.rs`; decision
record [0014](../docs/adr/0014-trust-graph.md).

- An owner's **authorization** is an Ed25519 signature over one program ID,
  naming its policy, privacy policy and purpose for one asset, with an
  optional expiry (`encompute.authorization.v1`). A **revocation**
  withdraws an asset or an authorization (`encompute.revocation.v1`). The
  report honours an asset's revocation only from an owner of the asset,
  and an authorization's only from its signer; any other revocation is
  ignored and noted.
- The **bundle** carries every piece of signed evidence inside its node.
  Its root is `tagged("encompute.trust-bundle.v1", canonical graph)`.
- The **report** rebuilds the graph from the evidence alone; any extra,
  missing or edited node, edge or attribute fails it. Signatures are
  checked only against keys the verifier passes (`--parties`,
  `--coordinator-key`, `--evaluator-key`). Evidence it cannot anchor is
  `PRESENT (not checked)`, and then the report is not `SATISFIED`.
- The report's execution row checks the receipt's signature and that its
  key is anchored or attested. It does not re-check the request and
  response commitments; that is the client's job (section 2). A receipt
  that claims an execution proof counts as proof only when the caller
  supplies a proof check; otherwise that step is unchecked.
- A plan's own context (profile, backends, development attestation) is
  not trusted: the report checks it against the caller's floor
  (`plan_floor`) and, when the caller supplies its compiler
  (`program_facts`), against the facts it computes for the program.
