# Release process

How an Encompute release is cut, gated, signed and published, starting
with 0.3. The short version:

1. Stabilize on a `release/0.3` branch; only fixes enter.
2. Bump to `0.3.0-rc.N`, run `scripts/release-check.sh`, sign off the
   security exceptions and the OpenFHE review.
3. Push the tag `v0.3.0-rc.N`. The `release` workflow builds, gates, signs
   and creates a **draft** release.
4. A maintainer reviews the draft and publishes it by hand.

Users verify what they download with [verify-release.md](verify-release.md).

## The release branch

`release/0.3` is cut from `main` when the 0.3 scope is complete. From then on:

- **What enters `release/0.3`:** security fixes, fixes for critical bugs
  (data loss, a broken security invariant, a crash on a documented path,
  a failing release gate), and release documentation (this file,
  verify-release.md, the changelog, release notes).
- **What does not:** features, refactors, dependency upgrades that are not
  security fixes, performance work, new examples. They go to `main` and ship
  in the next minor release.
- **How:** fix on `main` first, then cherry-pick (`git cherry-pick -x`) onto
  `release/0.3` through a pull request labelled `release/0.3`. A fix that only
  makes sense on the branch is committed there and noted in the PR. Each PR
  says which of the three categories it belongs to.
- **Who:** a release manager (a maintainer named in the release PR) merges
  into `release/0.3`; every merge needs one review and a green CI.
- After 0.3.0, the branch stays open for 0.3.x patch releases on the same
  rules, until 0.4.0 ships.

## Versioning

Semantic versioning. Release candidates carry `-rc.N`:

| Release | Git tag | Cargo (`[workspace.package] version`) | Python (`pyproject.toml`) |
|---|---|---|---|
| first candidate | `v0.3.0-rc.1` | `0.3.0-rc.1` | `0.3.0rc1` |
| next candidate | `v0.3.0-rc.2` | `0.3.0-rc.2` | `0.3.0rc2` |
| release | `v0.3.0` | `0.3.0` | `0.3.0` |
| patch | `v0.3.3` | `0.3.3` | `0.3.3` |

`v0.3.1` and `v0.3.2` exist only as failed release attempts. Neither has a
GitHub release or signed artifacts. Their tags are immutable, kept as
evidence, never moved or reused, and no artifact built from them is
supported (the public image tags `0.3.1` and `0.3.2` belong to them).

- `v0.3.1` stopped at the shipped-binary identity check, before signing,
  because the shipping build ran `env.sh` before exporting `OPENFHE_ROOT`,
  so the OpenFHE path remap was missing (see "The OpenFHE root comes first"
  below).
- `v0.3.2` fixed that, but its `release-check` job failed on two
  timing-based regression tests: the test helper took its two table locks
  with one `LOCK TABLE a, b`, which PostgreSQL acquires one table after the
  other, so under load the service could read before the simulated attacker
  held the second table. The product code was not at fault. The helper now
  proves the adversarial window or fails loudly as INCONCLUSIVE.

`v0.3.3` carries the same product code with the corrected helper and the
rehearsal below.

The Python version is the PEP 440 spelling of the same version.
`scripts/release/check-version.sh <tag>` checks that the tag, `Cargo.toml`,
`pyproject.toml` and `Cargo.lock` agree; the release workflow runs it first
and stops on a mismatch. An RC that passes unchanged becomes the release: the
final tag is placed on a commit that only changes the version.

## Cutting a release candidate

Run on a clean checkout of `release/0.3`. Nothing here pushes until step 7.

```sh
git switch release/0.3 && git pull --ff-only

# 1. Version (Cargo workspace, pyproject, the lock file).
N=1; V=0.3.0-rc.$N
sed -i.bak "/^\[workspace.package\]/,/^\[/s/^version = .*/version = \"$V\"/" Cargo.toml
sed -i.bak "/^\[project\]/,/^\[/s/^version = .*/version = \"0.3.0rc$N\"/" pyproject.toml
rm -f Cargo.toml.bak pyproject.toml.bak
cargo update -w
scripts/release/check-version.sh "v$V"

# 2. Pins still consistent; Python lock current.
scripts/release/check-pins.sh --network
scripts/release/lock-python.sh --check

# 3. Build the images the gates scan (or pass IMAGES= for ones you built).
docker build -f Dockerfile.evaluator -t encompute-evaluator:rc .
docker build -f Dockerfile.control -t encompute-control:rc .
docker build -f Dockerfile.services -t encompute-services:rc .
# The Confidential Space workloads (linux/amd64, as released):
docker buildx build --load --platform linux/amd64 -f deploy/confidential-space/Dockerfile \
  -t encompute-confidential-space:rc .
docker buildx build --load --platform linux/amd64 -f deploy/confidential-space-training/Dockerfile \
  --target production -t encompute-training:rc .

# 4. The one-command release check, with the services and the images.
ENCOMPUTE_TEST_DATABASE_URL=postgres://... ENCOMPUTE_TEST_BAO_ADDR=http://... \
ENCOMPUTE_TEST_BAO_TOKEN=... \
IMAGES="encompute-evaluator:rc encompute-control:rc encompute-services:rc encompute-confidential-space:rc encompute-training:rc" \
REQUIRE_IMAGES="encompute-evaluator encompute-control encompute-services encompute-confidential-space encompute-training" \
  scripts/release-check.sh --repro
```

5. **Security sign-off.** Read `target/release-scan/vulnerabilities.md`.
   For each blocking finding, fix it (a version bump, on the branch, if it is
   a security fix) or write an exception in `security/exceptions.toml`
   (below). Then the release manager reviews every exception and sets
   `approved_by` and `approved_on` in its `[approval]` table.
6. **OpenFHE review.** Check the sources listed in
   `security/openfhe-review.toml` for the pinned OpenFHE version, record any
   CVE, and set `reviewed_by` and `reviewed_on`.
7. Commit (`chore: 0.3.0-rc.1`), open the release PR, merge it, then tag the
   merged commit and push the tag:

   ```sh
   git tag -s "v$V" -m "Encompute $V"      # signed tag
   git push origin "refs/tags/v$V:refs/tags/v$V"
   git ls-remote origin "refs/tags/v$V"     # the SHA must be the local tag's
   ```

8. The `release` workflow (`.github/workflows/release.yml`) runs on the tag:
   the source archive, Linux x86_64 and macOS arm64 binaries and wheels, the
   three service images and the two Confidential Space workload images
   (pushed to `ghcr.io/<owner>/encompute-*`, private until published), SBOMs,
   the full release check with the services, signatures and provenance, and
   finally a **draft** GitHub release.
9. Review the draft: every expected file is there, `SHA256SUMS` lists them,
   the gate reports (workflow artifact `gate-reports`) show PASS, and the
   commands of verify-release.md succeed on the draft's files. Then publish
   the release and make the GHCR packages public.

A failed RC is never re-tagged: fix on the branch and cut `rc.N+1`.
`workflow_dispatch` runs the same pipeline as a dry run on any branch; it
signs the artifacts but creates no release.

## The rehearsal

A nonpublishing run of the complete Ubuntu 24.04 release path, on any branch:

```sh
gh workflow run release.yml --ref <branch> -f rehearsal=true
```

It runs only the `rehearse-*` jobs, each with a read-only token, no secrets,
no registry login and no signing, and creates no release. They:

- build the Linux binaries (`build-release-binaries.sh`) and the release
  tarball, as the `binaries` job does;
- build the five images locally (never pushed) and run the whole release
  check against exactly those, with Postgres and OpenBao;
- compare the shipped tarball's binaries with the ones the release check
  reproduced (`compare-shipped-digests.sh`), the check that stopped v0.3.1;
- run the five anchor window test files 20 times each under CPU load, and
  fail on any INCONCLUSIVE line other than the negative control's expected
  four.

It does not prove: signing, provenance attestation, the registry push, the
draft release, macOS builds, the wheel on macOS, Confidential Space or any
live check, or the Azure gate. A green rehearsal on one run is evidence about
that commit and that runner image, not about a later change.
`scripts/release/test-rehearsal-workflow.py` checks statically that the
rehearsal jobs stay gated and read-only.

**A `v*` tag must be preceded by a green rehearsal on the exact candidate
commit, and by the Azure gate on that commit.** Do not tag on the strength of
a rehearsal of a different commit.

## Checklist

Copy into the release PR.

- [ ] `rehearsal=true` run is green on the exact candidate commit, and the Azure gate has passed on it

- [ ] `release/0.3` contains only security fixes, critical bug fixes and release docs since the branch point
- [ ] versions bumped; `scripts/release/check-version.sh vX` passes
- [ ] base-image digests refreshed (`docker buildx imagetools inspect <image>`) and updated in `Dockerfile.*` and `deploy/confidential-space*/Dockerfile`
- [ ] `scripts/release/check-pins.sh --network` passes; `scripts/release/lock-python.sh --check` passes
- [ ] `python3 scripts/third_party_notices.py --check` passes (after `cargo fetch --locked`): `THIRD_PARTY_NOTICES.md` is current
- [ ] `scripts/release-check.sh --repro` passes with services and `IMAGES`, no `--allow-skip`
- [ ] the `release` workflow's step "Linux binaries are the ones the release check reproduced" is green (no signature exists without it)
- [ ] `security/exceptions.toml` reviewed and approved; no exception expires within 30 days
- [ ] `security/openfhe-review.toml` signed for the pinned version, within 90 days
- [ ] CHANGELOG.md has the release section
- [ ] tag pushed and read back with `git ls-remote`
- [ ] the `release` workflow is green; the draft has every artifact, `SHA256SUMS` and a `.sigstore.json` per file
- [ ] verify-release.md steps run against the draft's files
- [ ] draft published by a maintainer; GHCR packages made public
- [ ] live checks done by hand: Confidential Space training and key release (deploy/confidential-space*)

## The release gate

`scripts/release-check.sh` runs every gate and ends with a table. Each
required row must be PASS. A required row that is SKIPPED (its tool or
service is missing) fails the check; `--allow-skip` accepts skips for a local
run but never for a release. `--only "SecAgg,DP"` runs a subset (never a
release); `--list` prints each row's command.

| Row | Runs | Needs |
|---|---|---|
| Rust workspace | `cargo build --bins`, `cargo test`, `cargo clippy -D warnings` | |
| Python SDK | `maturin develop`, `pytest python/tests` (fine-tuning suites run in their own rows) | Python, pip network |
| OpenFHE CKKS | `cargo test -p encompute-runtime --features openfhe --test openfhe`, examples 01, 03, 19 on release binaries | OpenFHE |
| OpenFHE Exact | `cargo test -p encompute-openfhe-client -p encompute-openfhe-exact` | OpenFHE |
| optimized/reference diff | `cargo test -p encompute-exact --test circuit`; example 20 (optimized and reference evaluators must return the clear result) | OpenFHE for the encrypted half |
| remote execution | `cargo test -p encompute-runtime --test network`, `--test openfhe_exact`, `scripts/exact-demo.sh` | OpenFHE for the encrypted half |
| SecAgg | `cargo test -p encompute-secagg`, runtime `--test aggregation`, `test_aggregation.py`, example 08 | |
| DP | `cargo test -p encompute-privacy`, runtime `--test privacy`, `test_privacy.py`, example 09 | |
| patient DP-SGD | `test_dpsgd.py`, example 16 | |
| HF/PEFT | `test_huggingface.py`, example 17 | |
| control plane | `cargo test -p encompute-control -p encompute-keybroker -p encompute-verification` | `ENCOMPUTE_TEST_DATABASE_URL`, `ENCOMPUTE_TEST_BAO_ADDR`, `ENCOMPUTE_TEST_BAO_TOKEN` |
| tenant isolation | `cargo test -p encompute-control --test isolation` (every route unauthenticated, wrong role, other tenant; the cross-tenant attack suite) | same services |
| backup/restore | `scripts/release/backup-drill.sh` when present; else `scripts/enterprise-e2e.sh` (backup, restore, an older backup refused); else `deploy/docker-compose/smoke.sh` (backup, destroy, restore) | OpenFHE and the services and `pg_dump`/`psql`; or docker and the `:dev` images |
| assurance | `assurance-report` (every security invariant) | |
| commercial dependency | `scripts/audit-commercial-build.sh` on the release binaries, a wheel (built, or `WHEEL=`) and `IMAGES` | |
| SBOM | `scripts/release/sbom-all.sh`: one SBOM per artifact, checked | syft for images |
| security scans | `scripts/release/scan.sh` (below) | cargo-deny, cargo-audit, pip-audit; trivy or grype for images |

Reported rows (a FAIL fails the check, a SKIP does not): fine-tuning E2E,
examples, enterprise E2E, Compose deployment, build pins, the shipped
digests check (a selftest, below), reproducibility (`--repro`), TFHE-rs research, the Confidential Space image, and the live
Confidential Space checks, which need a GCP project and stay manual.

## Security scans and the severity policy

`scripts/release/scan.sh` writes its reports to `target/release-scan/`:

| Scanner | Scope | Gate |
|---|---|---|
| `cargo deny check` | the production feature graph (`deny.toml`): advisories, yanked crates, sources, licenses (a permissive allow-list; Encompute's own crates are AGPL-3.0), and the TFHE-rs ban | any error blocks |
| `cargo audit` | all of `Cargo.lock` (research crates included) | severity policy |
| `pip-audit` | `scripts/release/python/constraints.txt` (the SDK extras' pins) | severity policy |
| trivy (or grype) | each image in `IMAGES`: in the release workflow the three service images and the two Confidential Space workload images (`encompute-confidential-space`, `encompute-training`, production target); `REQUIRE_IMAGES` makes a missing one fail | severity policy |
| `python_licenses.py` | licenses of the Python pins, from PyPI | permissive pass; MPL-2.0 passes as reviewed (certifi, tqdm, used unmodified); anything else blocks |
| OpenFHE review | `security/openfhe-review.toml` | unsigned, stale (over 90 days) or for another version blocks |

`scripts/release/vuln_policy.py` applies one policy to every finding:

| Severity | Rule |
|---|---|
| **Critical, High** | Block the release. The only way past one is an approved exception with `status = "not_affected"` and a VEX justification (`vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`, `component_not_present`): an analysis that the flaw cannot be reached, not a waiver. |
| **Medium** | Blocks unless `security/exceptions.toml` has an approved entry (`accepted_risk` or `not_affected`). |
| **Low** | Reported in `vulnerabilities.md`. |
| unknown | Counts as High. |

The severity is the scanner's rating (trivy, grype), else the GitHub
advisory's rating, else a CVSS v3 base score computed from the advisory's
vector (through OSV). Exceptions:

- are narrow: one advisory (`id`: a CVE, GHSA, PYSEC, RUSTSEC, DLA, ...
  ID, matched against the finding's ID and aliases), one `package`, and the
  exact installed `version` the scanner reports (a list only for spellings
  of one release, such as pip-audit's `2.3.1` and trivy's `2.3.1+cpu`). An
  exception for torch 2.3.1 does not cover torch 2.3.2: a finding whose
  advisory and package match an exception for another version blocks and
  says so;
- are complete: `reason` (and, for `not_affected`, a VEX `justification`),
  `compensating_controls` (what keeps the code unreachable, stated from the
  code, with the test or gate that enforces it), `tracking` (the upstream
  advisory or issue, an https URL), `added` and `expires` (at most 183 days
  apart and from today);
- are approved: `[approval] approved_by` and `approved_on` cover the
  entries added on or before that date; an entry added later needs a new
  review (move `approved_on`) or its own `approved_by` and `approved_on`.
  These fields are text in the file, not signatures: an approval counts
  only through git review. Each change to `approved_by` or `approved_on`
  must be in a commit authored or reviewed by the release manager, in a
  pull request the owner named in `approved_by` approved;
- fail the gate when invalid (a missing field, a wildcard or list where one
  exact value is required, expired, unapproved), whether or not they match a
  finding; `scripts/release/test_vuln_policy.py` tests these rules and
  `scan.sh` runs it first;
- are reported as stale when nothing matches them, and removed at the next RC.

The torch and transformers exceptions rest on the shipped package never
calling `torch.load`, `torch.jit`, `torch.compile`, `torch.export`,
`torch.distributed`, the Transformers `Trainer` or accelerate's
`load_checkpoint_*`, and never passing `trust_remote_code=True`: the
"exception controls" row of `scan.sh` greps `python/encompute` and fails
if any appears.

Base-image OS packages: a Debian package with **no fixed version in the
distribution** is reported, not blocking; there is nothing to upgrade to.
Fixed ones block like everything else and are resolved by refreshing the
base-image digest. Every RC re-pulls and re-pins the digests.

`deny.toml` also ignores `RUSTSEC-2023-0071` (`rsa`, public-key use only); the
same advisory has an entry in `security/exceptions.toml` so it expires.

### OpenFHE

OpenFHE is a C++ library built from source; no advisory database covers it,
so the scanners cannot. For every release:

1. `scripts/install-openfhe.sh` pins the tag (`v1.5.1`) and refuses a
   checkout whose commit is not `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`;
   `check-pins.sh --network` confirms the upstream tag still resolves to it,
   and that `sbom.py` and the review name the same version and commit.
2. A reviewer checks the sources in `security/openfhe-review.toml` (GitHub
   security advisories, NVD, release notes, issues labelled security, the
   OpenFHE forum), records each CVE with whether the pinned version is
   affected, and signs the review. `scan.sh` fails otherwise.

### Scan results for 0.3 (2026-09-27, before sign-off)

| Source | Findings | State |
|---|---|---|
| cargo-deny (production graph) | none | PASS |
| cargo-audit | `rsa` RUSTSEC-2023-0071 (medium, no fix); unmaintained `bincode`, `paste` (research-only, through TFHE-rs) | exception proposed |
| pip-audit | torch 2.3.1: 2 critical, 8 high; transformers 4.46.3: 13 high; 17 medium; 6 low | exceptions proposed: none of the affected code paths is used (no `torch.load`, no Trainer, only BERT-family models, safetensors only, no Hub kernels in 4.46) |
| trivy, 3 images (Debian 12) | 1 fixable (tzdata DLA-4792-1); the rest have no Debian fix | exception proposed; unfixed reported |
| trivy, `encompute-confidential-space` (2026-09-29, linux/amd64) | tzdata DLA-4792-1; 227 with no Debian fix | excepted; unfixed reported |
| trivy, `encompute-training` production (2026-09-29, linux/amd64) | torch 2.3.1+cpu and transformers 4.46.3 (the pip-audit advisories above); installer tooling from the Python base image: jaraco.context 5.3.0 and wheel 0.45.1 (high, vendored in setuptools), pip 24.0 (5 medium), setuptools 79.0.1 (medium); OpenSSL 3.0.20-1~deb12u2 CMS/CMP (2 medium, fixed in 3.0.22-1~deb12u1); tzdata; 255 with no Debian fix | torch/transformers/tzdata excepted; 12 new exact-version exceptions proposed (not reachable: nothing in the workload runs pip, setuptools, wheel, CMS or CMP), pending approval; follow-ups: drop pip/setuptools/wheel from the production stage, refresh the base digest for OpenSSL |
| Python licenses | 29 permissive, 2 MPL-2.0 reviewed | PASS |

The ML stack pins (torch 2.3, transformers 4.46, peft 0.12) are what the
confidential training image and every model package bind; moving them
changes the image digest and the package format, so it is not a release-branch
change. It is the first item for 0.4, and the exceptions expire on
2026-12-31 to force it.

## SBOMs

`scripts/sbom.py --artifact cli|evaluator|control|wheel` writes a CycloneDX
1.5 SBOM per artifact: every Rust crate (normal dependencies only, with the
features the artifact is built with) and its license, the dependency graph,
OpenFHE as a component with its version, commit, BSD-2-Clause license and
static linkage, the artifact's SHA-256, and, for the wheel, the pinned Python
packages of its extras (scope `optional`, with licenses). Timestamps come
from `SOURCE_DATE_EPOCH` and the serial number from the content, so the SBOM
of a commit is reproducible. Images get a syft SBOM, attached to the image as
a signed cosign attestation. `sbom-all.sh` generates all of them and fails on
a malformed SBOM, a missing OpenFHE component or any TFHE-rs component.

## The research dependency boundary

TFHE-rs (Zama) is research-only: commercial use needs a patent license, so
no release artifact may contain it. It is checked five ways, and each fails
the release: `cargo deny` bans the `tfhe*` and `concrete*` crates in the
production graph; `audit-commercial-build.sh` checks the graph, the combined
SBOM, the symbols and libraries of every binary, the wheel's native
extension, and every image (Python packages, file names, and the symbols of
the binaries in `/usr/local/bin`); `sbom-all.sh` checks every SBOM. The
research build (`--features research-tfhe-rs`) is exercised in CI only, and
CI checks that the commercial audit rejects it.

## Signing and provenance

The `release` job signs with Sigstore keyless signing: GitHub's OIDC token
identifies the workflow (`release.yml` on the tag), Fulcio issues a
short-lived certificate for it, and the signature is logged in Rekor. There
is no key to store or leak.

- Every file (and `SHA256SUMS`) gets a Sigstore bundle, `<file>.sigstore.json`
  (`cosign sign-blob --bundle`).
- Every image is signed by digest (`cosign sign`) and carries its SBOM as a
  signed attestation (`cosign attest --type cyclonedx`).
- `actions/attest-build-provenance` records SLSA provenance for every file
  (from `SHA256SUMS`) and every image, verifiable with `gh attestation verify`.
- The Confidential Space workload images, `encompute-confidential-space`
  (key release) and `encompute-training` (the training worker, `production`
  target), are built, SBOM'd, audited by `audit-commercial-build.sh`, signed
  and attested like the service images. Their digests, the ones key brokers'
  attestation policies approve, are listed in `encompute-<V>-tee-images.txt`
  (signed with the other files) and in the release notes.
- The released `encompute-confidential-space` image is a base reference,
  not a deployable workload: it is built without `broker-keys` (the
  Dockerfile's `COPY broker-key[s]` is optional), so its `run-workload.sh`
  refuses to start (the image names no broker keys). A deployment builds
  its own image with `deploy/confidential-space/deploy.sh`, which writes
  the broker's grant-signing key into `broker-keys`; the digest its key
  broker approves is that build's, not the released one. Compare the
  release digest to check the build inputs, not to approve a workload.

The workflow's permissions are per job: only the jobs that sign get
`id-token: write`; only the release job gets `contents: write`; only the
image job gets `packages: write`. Actions are pinned by commit SHA (see
Pins).

## Reproducibility

### Pins

| Input | Pinned by | Checked by |
|---|---|---|
| Rust | `rust-toolchain.toml` (1.98.1); the workflows use `dtolnay/rust-toolchain@<sha> # 1.98.1` (except `fuzz.yml`, which needs nightly and builds no release artifact); the images `rust:1.98.1-bookworm@sha256:…` | `check-pins.sh` |
| Rust crates | `Cargo.lock`; every build uses `--locked` | `check-pins.sh`, cargo-deny `sources` |
| OpenFHE | tag `v1.5.1`, commit `1306d14f…` verified at install | `install-openfhe.sh`, `check-pins.sh --network` |
| Python | `scripts/release/python/constraints.txt`: hashed pins for CPython 3.11, Linux x86_64, from `requirements-release.in` (which includes the training image's `requirements.txt`) | `lock-python.sh --check`, `check-pins.sh` (the lock must match the image's pins and satisfy pyproject's extras) |
| Training image Python | `deploy/confidential-space-training/requirements.lock`: every package and file hash for CPython 3.11, Linux x86_64, installed with `pip --require-hashes --no-deps`; the same versions as the release lock. The image's build tools come from `build-requirements.lock`, also hashed | `check-pins.sh` (every pin must be in the release lock) |
| Base images | `Dockerfile.*` and `deploy/confidential-space*/Dockerfile` `FROM …@sha256:` (multi-arch index digests) | `check-pins.sh` |
| Actions | every `uses:` in `.github/workflows/*.yml` is `@<40-hex commit SHA> # <version>` | `check-pins.sh` |

**The Python lock is resolved at a recorded time.** `scripts/release/python/lock-cutoff.txt` holds one fixed RFC 3339 UTC timestamp (now `2026-10-17T20:49:00Z`). `lock-python.sh` passes it to `uv pip compile --exclude-newer` in both modes, so uv resolves only what PyPI published before that instant, and `--check` asks the same question every time: it fails only when `constraints.txt` differs from what the declared inputs resolve to at the recorded cutoff. A package that publishes later no longer makes the check fail; the release lock does not drift. The generated header of `constraints.txt` repeats the cutoff. To update the lock, set `lock-cutoff.txt` to a later time (the current UTC time, to the minute; it must be later than the upload of every artifact you expect), run `scripts/release/lock-python.sh`, then regenerate the training image's lock from `deploy/confidential-space-training` and commit both:

```sh
uv pip compile requirements.txt -c ../../scripts/release/python/constraints.txt \
  --python-version 3.11 --python-platform x86_64-manylinux_2_28 \
  --extra-index-url https://download.pytorch.org/whl/cpu --index-strategy unsafe-best-match \
  --exclude-newer "$(cat ../../scripts/release/python/lock-cutoff.txt)" \
  --generate-hashes --no-header -o requirements.lock
```

Use uv 0.13.0 for both. The PyTorch CPU index publishes no upload times: uv warns that each of its files is "missing an upload date" and treats it as uploaded at the cutoff, so that index is not filtered by time. Only the exact pins taken from it (`torch==2.3.1`, from the training image's `requirements.txt`) and their hashes are read from it live.

**C++ toolchain.** OpenFHE and the cxx bridges are compiled by the host's
C++ compiler; it is recorded, not pinned. Release Linux builds use the
`ubuntu-24.04` runner's GCC 13 and CMake 3.28+; the evaluator image uses
Debian 12's GCC 12 (`rust:1.98.1-bookworm`); macOS builds use Apple clang
from Xcode on `macos-14` with Homebrew's `libomp`. OpenFHE needs a C++17
compiler, CMake 3.16 or later and OpenMP. `check-pins.sh` prints the local
compiler and CMake versions for the record.

### The build environment

`scripts/release/env.sh` is sourced by every release build:

- `SOURCE_DATE_EPOCH` = the commit time (anything that stamps a date uses it);
- `--remap-path-prefix` for the checkout, the target directory, cargo's
  registry, rustup and `OPENFHE_ROOT`, and `-ffile-prefix-map` for C/C++, so
  no local path enters a binary (`/target`, `/encompute`, `/cargo`, `/rustup`,
  `/openfhe`, and `/openfhe-src` inside OpenFHE's own objects);
- `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`, `CARGO_PROFILE_RELEASE_DEBUG=0`,
  `CARGO_INCREMENTAL=0`; symbols are kept (the audits read them);
- `ZERO_AR_DATE=1` for macOS archives.

#### The OpenFHE root comes first

`env.sh` computes the OpenFHE path remap once, from the `OPENFHE_ROOT` it sees
when it is sourced, so the root must be known before. The contract:

- `OPENFHE_ROOT` unset (or empty) and `<repo>/.deps/openfhe` exists: that
  directory is the root.
- `OPENFHE_ROOT` set: it is used exactly as given and never replaced. It must
  be an absolute path without a trailing slash, with
  `include/openfhe/pke/openfhe.h` and the three static libraries
  `install-openfhe.sh` installs, or sourcing `env.sh` fails with an error.
  An inherited wrong value (a leftover `OPENFHE_ROOT` from a service
  environment file, for example) is therefore an error or a visibly different
  root, never a silent substitution: a caller that means another root
  exports it before sourcing.
- Exporting `OPENFHE_ROOT` after sourcing `env.sh` is the v0.3.1 defect: no
  OpenFHE remap, different binaries. Every caller exports first
  (`build-release-binaries.sh`, the wheel step, `repro-check.sh`).

`scripts/release/build-release-binaries.sh [TARGET_DIR]` is the shipping
build of the three binaries (resolve and validate the root, source `env.sh`,
check that the three flag sets remap it, `cargo build --release --locked`).
The `binaries` job and the diagnostic run it; `repro-check.sh` stays the
gate's own builder. `scripts/release/test-env-openfhe.sh` and
`test-build-release-binaries.sh` are their self-tests.

#### The binary path guard

`scripts/release/check-binary-paths.sh BINARY...` fails if the strings of a
binary contain `/.deps/`, `/openfhe-development`, or a path under `/home/`,
`/Users/`, `/root/`, `/tmp/`, `/var/`, `/builds/` or `/runner/`; the fixed
remap targets above are the only prefixes a path may start with. It runs on the
Linux binaries in the `binaries` job (right after they are built), in
`repro-check.sh` on Linux, and, report only, in the diagnostic. The macOS
binaries are not checked (their path forms have not been inspected). An
exception goes in `scripts/release/binary-paths.allow` with a one-line
justification; there are none, and a path is almost always fixed by remapping
it instead. `test-check-binary-paths.sh` is the self-test.

#### The diagnostic dispatch

A nonpublishing run that builds the release binaries in several
configurations on two clean runners and compares the digests (no tag, no
signing, no registry login, no release; the release jobs are skipped):

```sh
gh workflow run release.yml --ref <branch> -f diagnostic=true
```

`scripts/release/diag-openfhe-order.sh` builds the configurations: A0 and A
(the old order, labelled expected to differ and not part of any pass or fail),
B and C (the shipping build, `build-release-binaries.sh`, twice) and D (the
gate's `repro-check.sh`, twice), then `diag-compare-jobs.sh` compares them
within and across the two jobs. A healthy result is B = C = D1 = D2 inside
each job and across both jobs, with A different, and the path guard's report
clean for B, C and D. Use it whenever the build environment, the toolchain
image or `install-openfhe.sh` changes.

Release tarballs are written by `scripts/release/pack.py` (sorted entries,
fixed owner and modes, `SOURCE_DATE_EPOCH` mtimes, a zeroed gzip header) and
the source archive by `git archive | gzip -n`, so both are byte-stable.

### The check

`scripts/release/repro-check.sh` builds the release binaries twice, each in
a new target directory at a different path, and compares SHA-256
(`--openfhe`: the three release binaries with OpenFHE; the release workflow
runs it through `release-check.sh --repro`). Results on 2026-09-27, macOS
arm64, Apple clang 21:

| Binary | Result |
|---|---|
| `encompute` (no OpenFHE) | byte-identical (`d75e2434…`) |
| `encompute-evaluator` (OpenFHE, static) | byte-identical (`5818176e…`) |

### The signed Linux binaries are the reproduced ones

The `binaries` job builds the Linux release binaries and packages them
(`encompute-VERSION-linux-x86_64.tar.gz`) on its own runner. The
`release-check` job builds them again, twice, with `repro-check.sh`, and its
tests and scans run on its own build, so the packaged build and the
reproduced build are different builds of the same commit. They are bound
together by digest:

- `repro-check.sh --digests FILE` writes `sha256  name` for each of the
  three binaries (`encompute`, `encompute-evaluator`, `encompute-control`)
  only when both of its builds were byte-identical. `release-check.sh
  --repro` passes `target/release-scan/repro-digests.txt`, which is uploaded
  among the gate's reports (workflow artifact `gate-reports`).
- The `release` job downloads `gate-reports` and runs
  `scripts/release/compare-shipped-digests.sh
  gate/release-scan/repro-digests.txt dist/encompute-VERSION-linux-x86_64.tar.gz`
  before the checksums, the signatures, the attestation and the draft
  release. It computes the SHA-256 of each binary inside the tarball and
  fails the job on a mismatch, a missing or extra binary (anything in the
  tarball but the three binaries and the licence files), a digest recorded
  for another name, a missing, empty or truncated digest file, a repeated
  name, or the digest of empty input (`e3b0c442...52b855`).
- The check relies on the build being reproducible across the two jobs (same
  commit, runner image and pinned inputs). If the two differ, the release
  fails closed and is investigated as a reproducibility failure.
- `scripts/release/test-compare-shipped-digests.sh` is the selftest of the
  comparison (a matching tarball passes; a changed byte, a missing binary,
  an extra binary, an empty, wrong-name or truncated digest file each fail)
  and of `--digests`; `release-check.sh` runs it, with the self-tests of
  `env.sh`, `build-release-binaries.sh` and `check-binary-paths.sh`, as the
  row "shipped digests check".
- Not covered: the macOS arm64 binaries and the wheels have no gate build.
  They are built once, by the `binaries` job, and are the workflow's output
  at the tagged commit signed with the same identity.

### What still varies, and why

- **The OpenFHE static library.** It is built once per machine by
  `install-openfhe.sh` with the host compiler, and linked into the CLI, the
  evaluator and the wheel. Two builds against the *same* OpenFHE install are
  identical (above); builds against OpenFHE compiled by a different compiler
  version, or with different CPU flags, differ in the OpenFHE code. Its CMake
  build maps its source and install directories to `/openfhe-src` and
  `/openfhe` (`-ffile-prefix-map`, build id `static-4`), so the OpenFHE objects
  do not depend on the checkout path. The release workflow compiles OpenFHE
  fresh on the runner (no cache), so a rebuild on the same runner image
  reproduces it. That the two CI jobs' OpenFHE builds are byte-identical is
  shown by the diagnostic run, not assumed.
- **macOS code signatures.** The linker's ad-hoc signature is derived from
  the content and is reproducible. A Developer ID signature (not used for
  0.3) would add a signing time and a certificate, and differ per signing.
- **Python wheels.** maturin stamps zip entries from `SOURCE_DATE_EPOCH`, but
  on Linux `--auditwheel repair` copies `libgomp` into the wheel under a
  content-hashed name and rewrites the extension's RPATH; the result depends
  on the runner's libgomp. Compare the extension inside the wheel, not the
  wheel file.
- **Container images.** Layer timestamps are rewritten to `SOURCE_DATE_EPOCH`,
  but `apt-get install` takes whatever Debian serves on the day, so image
  digests change between builds even from the same base digest. The release's
  images are identified by the digests recorded in the release, not rebuilt.
- **Linux vs. macOS.** Different targets; never expected to match.

## Known issues (0.3)

- **macOS: OpenMP.** The macOS binaries built with OpenFHE link Homebrew's
  `libomp` by absolute path (`/opt/homebrew/opt/libomp/lib/libomp.dylib`), so
  they need `brew install libomp`. The release wheel bundles its `libomp`
  (`maturin --auditwheel repair`), but that is a second OpenMP runtime next
  to PyTorch's bundled `libomp`; a process that uses both (the OpenFHE SDK and
  `encompute.torch`) crashes in PyTorch's first parallel operator (seen in
  `test_confidential_job.py`: segmentation fault in `layer_norm`).
  `OMP_NUM_THREADS=1` avoids it at a performance cost. Release check runs
  the encrypted examples in a separate environment without PyTorch
  (`target/release-check-venv`). A fix (bundling one runtime with
  `delocate`, or linking OpenFHE against PyTorch's) is outside the freeze;
  until then the macOS wheel should be documented as "OpenFHE or PyTorch,
  not both in one process", or not shipped.
- **Flaky capability probe in the examples.** `examples/lib.sh` `has()` runs
  `"$E" info | grep -q ...` under `pipefail`; when `grep -q` exits first, the
  CLI gets a broken pipe and the probe reports the feature as missing
  (measured: 21 of 300 probes). A required example is then "skipped" and the
  row fails. Fix: `grep "^$1 *yes" >/dev/null` (read all input). Until it
  lands, rerun a row that fails with "required, but skipped".
- **Linux binaries need glibc 2.39** (built on Ubuntu 24.04). The images
  are unaffected (built on Debian 12 inside the image).

## What stays manual

- Approving `security/exceptions.toml` and signing the OpenFHE review.
- The live Confidential Space checks (training with real attestation, key
  release), which need a GCP project.
- Reviewing and publishing the draft release; making the GHCR packages public.
- Creating the `release/0.3` branch and pushing tags.
