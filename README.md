# Encompute

**Encompute is a compiler and trust runtime for confidential AI and
cross-organization computation.**

Organizations can compute, train and collaborate over sensitive data without
centralizing the underlying records or surrendering control of their keys.
Encompute combines confidential computation with purpose-bound authorization,
privacy controls, governed release, lineage and auditable evidence.

The execution layer can use fully homomorphic encryption (FHE), secure
aggregation, differential privacy and attested confidential computing,
depending on the workload. The security boundary is not the application or the
AI model: authorization and release decisions are enforced by Encompute and by
organization-controlled key brokers.

> **Release status:** `v0.3.0` is the current stable release. `main` contains
> substantial unreleased governance and security work intended for the next
> release line. That work is not part of a stable release and should not be
> described as production-ready.

You write ordinary Python and mark which values are secret. Encompute encrypts
them, runs the program on a machine that never holds the key, and checks the
answer against plain Python.

## Who it is for

- **AI and application teams** that need useful answers from sensitive data
  without exposing the underlying records to every component in the workflow.
- **Security, privacy and compliance teams** that need enforceable controls
  over purpose, authorization, key release, privacy loss and result release.
- **Organizations collaborating across trust boundaries** that need to compute
  or train together while retaining ownership, key custody and independent
  authorization.
- **Regulated and sovereign environments** that require auditable evidence of
  what was authorized, computed and released.

## What makes Encompute different

Most privacy-preserving computation libraries answer one question: how do I
compute on encrypted data? Encompute also answers:

- Who authorized this computation?
- For what purpose?
- Over which exact assets and versions?
- Which organization controls each key?
- What information may be released?
- What privacy budget was consumed?
- What evidence remains afterward?

The cryptographic backend is one part of the system. Encompute's trust runtime
connects policy, authorization, confidential execution, controlled release,
lineage and evidence.

## What it guarantees, and what it does not

It guarantees, for the supported features
([support matrix](docs/support-matrix.md)):

- The machine that does the computing never gets the secret key. It sees
  encrypted values, not your data.
- Unsafe programs are refused when they are compiled: branching on a secret,
  printing it, or a number that could overflow.
- Encrypted results are checked against plain Python, within a precision you
  declare.
- Between organizations, rules about who may learn what are checked by the
  compiler. Keys can be released only to a workload that proves what it is
  (experimental on Google Confidential Space).

It does **not**:

- Hide the program. The computing machine sees the operations, public
  constants, shapes, declared ranges, timing and data sizes.
- Prove that the computing machine did the work honestly. A receipt is a
  signed claim. Proofs exist only in a research build.
- Protect data after you decrypt it and share it.
- Come with a proof of security for the whole system. The
  [known limitations](KNOWN_LIMITATIONS.md) list the rest. Read them before
  you use real data.
- Run fast. Encrypted computation costs far more than plain computation
  ([performance](docs/performance.md)).

Terms used here. **FHE** (fully homomorphic encryption): computing on
encrypted data. **CKKS**: an FHE scheme for real numbers, correct to a
declared precision. **SecAgg** (secure aggregation): parties add their
private vectors so that only the sum is revealed. **DP** (differential
privacy): added noise that limits what published results reveal about any
one person. **TEE** (trusted execution environment): hardware that can prove
what software it runs.

## Try it in five minutes

You need Python 3.11 or later. This installs the released package (macOS on
Apple silicon shown; the [release](https://github.com/BAder82t/Encompute/releases/tag/v0.3.0)
has a wheel for Linux x86_64 too) and runs the starter,
[example 00](examples/00_hello_encrypted/):

```sh
git clone https://github.com/BAder82t/Encompute && cd Encompute
python3 -m venv .hello && . .hello/bin/activate
gh release download v0.3.0 -R BAder82t/Encompute -p 'encompute-0.3.0-cp311-abi3-macosx_11_0_arm64.whl'
pip install ./encompute-0.3.0-cp311-abi3-macosx_11_0_arm64.whl
examples/00_hello_encrypted/run.sh
```

Real output from that wheel (sizes and timings vary from run to run; the
last step, three refusals of unsafe actions, is left out here):

```text
== Score four private test results without revealing them ==
Step 1. The clinic's private data (the evaluator never sees this)
  panel = [0.62, 0.18, 0.91, 0.4]

Step 2. What the risk service is told: the program, not the data
  scheme    CKKS (approximate), 128-bit classical
  the evaluator can see:
    - program structure (operations and their order)
    - public constants (weights, coefficients)
    - input and output shapes
    - declared input ranges
  evaluator receives the secret key: no

Step 3. Encrypt, compute while encrypted, decrypt
  (the sizes below come from a second encrypted run with fresh keys)
  the clinic made a secret key and public keys, and encrypted the panel
  the evaluator received 1,574,609 bytes of ciphertext
    and 18,882,955 bytes of evaluation keys (no secret key)
  the evaluator computed sigmoid(weights . panel + bias) on ciphertext
  it returned 526,087 bytes: one ciphertext only the clinic can open
  the clinic decrypted it (timings in ms: keygen 460, encrypt 21, evaluate 94, decrypt 11)

Step 4. Check the answer against plain Python
  plain result      0.77171
  encrypted result  0.77161
  difference        0.00010  (allowed: 0.00100)
```

A clinic's four private numbers were encrypted, scored by a service that
never saw them in the clear, and decrypted. The scoring side held no secret
key.
The example's README explains each step and what it does not show.

## Pick your path

| You are | Read | Then run |
|---|---|---|
| Developer | [Developer path](docs/guide/developer.md) | [01](examples/01_ckks_private_inference/), [02](examples/02_exact_private_logic/) |
| Security or compliance lead | [Security and compliance path](docs/guide/security-and-compliance.md) | [06](examples/06_confidentiality_policy/), [13](examples/13_assurance_suite/) |
| Institution deploying it | [Institution path](docs/guide/institutions.md) | [11](examples/11_automatic_planner/), [12](examples/12_confidential_collaboration/) |

Every capability has a runnable example; [examples/](examples/README.md)
has a table by goal. All topics are in the [guide](docs/guide/README.md):
[confidentiality policies](docs/guide/confidentiality-policies.md),
[secure aggregation](docs/guide/secure-aggregation.md),
[differential privacy](docs/guide/differential-privacy.md),
[planner](docs/guide/planner.md),
[confidential fine-tuning](docs/guide/confidential-fine-tuning.md),
[trust graph](docs/guide/trust-graph.md),
[attested key release](docs/guide/attested-key-release.md),
[verification](docs/guide/verification.md),
[remote evaluation](docs/guide/remote-evaluation.md) and
[building from source](docs/guide/build.md).

## Status and support

**Stable:** `v0.3.0`. It includes the confidential-computation
compiler and runtime, OpenFHE-backed encrypted execution, secure aggregation,
differential privacy, trust and evidence machinery, confidential fine-tuning,
and the documented 0.3 support surface.

**Development (`main`):** additionally contains unreleased work for governed
cross-organization computation: purpose-bound authorization,
organization-controlled governance keys, revocation, multi-owner key custody,
governance lineage and event logging, privacy-budget governance, and hardened
production deployment infrastructure. Development-branch functionality is not
part of `v0.3.0` and should not be treated as a stable or production-ready
release.

What is supported, what is a subset, and what is experimental, research only
or unsupported is in the [support matrix](docs/support-matrix.md), with a short
[summary](docs/guide/status-summary.md). Also: [known limitations](KNOWN_LIMITATIONS.md),
[release notes](docs/release-notes-0.3.0.md), [changelog](CHANGELOG.md),
[threat model](docs/threat-model.md), [security findings](docs/security-findings.md),
[repository layout](docs/guide/layout.md) and [roadmap](docs/guide/roadmap.md).

An independent review of 0.3.0-rc.3 reported findings that are fixed in
0.3.0, some only partly. The reviewers have not reviewed the fixes.
Security reports: [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-only, with commercial licenses available: see [LICENSING.md](LICENSING.md).
Encompute statically links OpenFHE (BSD 2-Clause); research builds with the
`research-tfhe-rs` feature also link TFHE-rs (BSD-3-Clause-Clear, plus Zama's patent
terms); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
