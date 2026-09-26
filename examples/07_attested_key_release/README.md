# 07 — Attested key release

## What this demonstrates

An asset owner's key broker releases a decryption key only to a workload
that proves, with fresh hardware evidence, that it is the approved image
running the approved artifact under the approved confidentiality policy.
Everything runs locally with the development-only mock attestation
provider; no cloud account is needed.

1. ModelCo writes an attestation policy for `step.encompute` (image, TEE,
   ExecutionSpecID, PolicyID, artifact digest) and protects its `weights`
   key under it.
2. The broker issues a challenge (a fresh nonce). The workload answers with
   evidence that binds the nonce, the spec, the policy and a fresh session
   key.
3. The broker verifies the evidence and the policy, then returns the key
   sealed to that session (a grant only that session can open).
4. The same flow over HTTP: Hospital A's and ModelCo's brokers, one
   workload that receives both keys, and an evaluator whose receipts the
   client verifies against the attestation.

## Threat model

The host that runs the workload is untrusted: it may run a modified image,
another artifact, replay old evidence, or swap in its own keys. The TEE
hardware (here: a mock of it) and each owner's key broker are trusted. The
mock provider signs whatever it is told to: it stands in for hardware so
the checks can be exercised, and protects nothing.

## Architecture

```text
key broker (owner)                      workload (in a TEE)
policy.json + wrapped key
challenge (nonce) ────────────────────► evidence: nonce, image, spec, policy,
                                                  session key (signed by the TEE)
verify evidence ◄──────────────────────┘
check policy
grant = key sealed to the session ────► opens it inside the TEE only
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/07_attested_key_release/run.sh
```

It runs in `examples/run-all.sh standard` (it starts local servers).

## Expected output

```text
ATTESTATION VERIFIED
ATTESTATION          VERIFIED (mock, mock (development only))
POLICY               SATISFIED
KEY RELEASE          AUTHORIZED (key version 1, sealed to the session: grant.json)
SEALED KEY GRANT  asset weights, key version 1, one attested session
Grant fields      encapsulated_key, ciphertext (no plaintext key)

ATTACK   replay the same evidence (its challenge nonce is used up)
REFUSED  KEY RELEASE          REFUSED: ENC2003: the evidence answers no open challenge (unknown, expired or already used)
ATTACK   same artifact, another ExecutionSpecID (openfhe backend)
REFUSED  KEY RELEASE          REFUSED: ENC2002: the workload is bound to execution spec ..., not ...
ATTACK   another artifact with a weaker policy (other PolicyID)
REFUSED  KEY RELEASE          REFUSED: ENC2002: the workload is bound to execution spec ..., not ...
ATTACK   a modified workload image
REFUSED  KEY RELEASE          REFUSED: ENC2002: workload image sha256:modified is not allowed
ATTACK   the host swaps in another session's key
REFUSED  KEY RELEASE          REFUSED: ENC2001: the evidence does not commit to this workload binding
ATTACK   a modified workload asks both brokers
REFUSED  error[ENC2002]: broker: workload image sha256:modified is not allowed
Key           patients v1 from hospital: RECEIVED (32 bytes, sealed to this session)
Key           weights v1 from modelco: RECEIVED (32 bytes, sealed to this session)
WORKLOAD ATTESTATION VALID
RECEIPT VERIFIED
EXECUTION PROOF NOT PRESENT
```

The `ATTESTATION`, `POLICY` and `KEY RELEASE` lines are the CLI's own
(`encompute keys release`). `SEALED KEY GRANT` and `Grant fields` are this
script's summary of the grant file.

## Try breaking it

Staged by `run.sh`:

| Attack | How | Refused with |
|---|---|---|
| Replayed evidence (used nonce) | present the same evidence twice | ENC2003 |
| Wrong ExecutionSpecID | attest the same artifact for the `openfhe` backend | ENC2002 |
| Wrong PolicyID | attest `relaxed.eir`, which lets ModelCo see gradients too | ENC2002 |
| Modified image | mock evidence for `sha256:modified` | ENC2002 |
| Wrong session key | the host puts another session's key into genuine evidence | ENC2001 |

The ExecutionSpecID commits to the confidentiality policy, so an artifact
with another PolicyID also has another spec ID; the broker reports the spec
mismatch first. A PolicyID-only mismatch cannot be produced from the CLI.

Not stageable from the CLI, covered by Rust tests instead:

| Attack | Why not here | Test |
|---|---|---|
| PolicyID differs, spec the same | see above | `crates/encompute-keybroker/tests/release.rs::untrusted_workloads_receive_no_key` ("wrong policy"), `crates/encompute-attestation/tests/attestation.rs::policy_mismatches` (ENC2002) |
| Debug workload | the mock attester has no debug switch on the CLI | `release.rs::untrusted_workloads_receive_no_key` ("debug"), `attestation.rs::debug_and_tcb` (ENC2002) |
| Stale or expired evidence, expired challenge | needs a controllable clock | `release.rs::untrusted_workloads_receive_no_key`, `attestation.rs::freshness` (ENC2003) |
| Grant opened by another session | `workload attest` discards its session key, and no command opens a grant | `attestation.rs::grants_open_only_in_their_session` (ENC2004) |

A real Google Confidential Space variant would need GCP credentials and is
not part of this suite; see `deploy/confidential-space/README.md`.

## What Encompute guarantees

- A broker releases a key only for evidence that answers one of its own
  unused challenges and satisfies the policy: image, TEE, TCB, debug state,
  ExecutionSpecID, PolicyID and artifact digest.
- The key leaves the broker only sealed to the session key the evidence
  commits to; the grant never contains it in the clear.
- Production policies and production brokers refuse mock evidence
  (ENC2002).
- Receipts from the evaluator bind the attestation record, so a client can
  check which attested workload produced a result.

## What Encompute does NOT guarantee

- Mock attestation protects nothing: anyone with the seed file can produce
  "valid" evidence for any image. It exists to exercise the checks.
- With real hardware, Encompute relies on the TEE vendor and attestation
  service: a hardware flaw or a compromised vendor key defeats it.
- Attestation says which image runs, not that the image is free of bugs or
  leaks. Owners must review what they approve.
- A receipt is a signed claim, not a proof of correct execution
  (`EXECUTION PROOF NOT PRESENT`).
- Once a workload holds a key, what it does with the data is up to the
  approved code; revoking a key stops future releases only.

## Relevant source modules

- `crates/encompute-attestation`: evidence, policies, the mock and
  Confidential Space providers, sealed grants.
- `crates/encompute-keybroker`: challenges, release, key storage,
  `keys serve`, `workload keys`.
- `crates/encompute-cli/tests/cli.rs::attestation_and_key_release`: the CLI
  flow this example follows.
- `docs/errors.md` (ENC2001 to ENC2004), `docs/adr/0011-attested-key-release.md`
  (design).
