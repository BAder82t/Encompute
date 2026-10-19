# Verifying a release

Every Encompute release is built by the `release` workflow of
[BAder82t/Encompute](https://github.com/BAder82t/Encompute) from a tag, and
every file is signed with Sigstore keyless signing: GitHub Actions proves the
workflow's identity to Sigstore through OIDC, and no long-lived key exists.
There are three independent checks. Do all three before you deploy a
release; each one takes a few seconds.

1. **Checksums**: the files you downloaded are the files that were released.
2. **Signatures** (cosign): the files, and the container images, were signed
   by this repository's release workflow running on a release tag.
3. **Attestations** (GitHub): GitHub records which workflow run, commit and
   runner built each file and image (SLSA build provenance).

You need `sha256sum` (or `shasum` on macOS), [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.4 or later, and the [GitHub CLI](https://cli.github.com/) 2.49 or later.
The examples use `v0.3.3`, the current supported release; replace it with the
release you verify. Do not use `v0.3.1` or `v0.3.2`: they were incomplete
release attempts with no signed artifacts (see [SECURITY.md](../SECURITY.md)).

```sh
TAG=v0.3.3
V=${TAG#v}
REPO=BAder82t/Encompute
# The only identity allowed to sign a release: the release workflow, on a tag.
ID='^https://github\.com/BAder82t/Encompute/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
ISSUER=https://token.actions.githubusercontent.com
```

## What a release contains

| File | What it is |
|---|---|
| `encompute-$V-source.tar.gz` | `git archive` of the tagged commit |
| `encompute-$V-linux-x86_64.tar.gz` | `encompute`, `encompute-evaluator`, `encompute-control`, built with OpenFHE (glibc 2.39 or later: Ubuntu 24.04, Debian 13) |
| `encompute-$V-macos-arm64.tar.gz` | the same for macOS 11+ on Apple silicon (needs `brew install libomp`) |
| `encompute-$V-*.whl` | the Python SDK (`encompute`), with OpenFHE |
| `*.cdx.json` | a CycloneDX SBOM for each binary, wheel and image |
| `encompute-$V-images.txt` | the evaluator, control and services container images, by digest |
| `encompute-$V-tee-images.txt` | the Confidential Space workload images (`encompute-confidential-space`, `encompute-training`), by digest |
| `SHA256SUMS` | the SHA-256 of every file above |
| `*.sigstore.json` | the Sigstore bundle (signature, certificate, transparency-log proof) of each file |

## 1. Checksums

```sh
gh release download "$TAG" -R "$REPO" -D "encompute-$V"
cd "encompute-$V"
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```

Every line must end in `OK`. A checksum file is only as good as its
signature, so continue with step 2.

## 2. Signatures (cosign)

`SHA256SUMS` first: once it is verified, the checksums bind every other file.

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$ID" \
  --certificate-oidc-issuer "$ISSUER"
```

`Verified OK` means: this exact file was signed by the release workflow of
`BAder82t/Encompute`, running on a `vX.Y.Z` or `vX.Y.Z-rc.N` tag, and the
signature is recorded in Sigstore's public transparency log (Rekor). Any
file can be checked the same way:

```sh
f="encompute-$V-linux-x86_64.tar.gz"
cosign verify-blob "$f" --bundle "$f.sigstore.json" \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"
```

To pin one exact tag instead of any release tag, use
`--certificate-identity "https://github.com/BAder82t/Encompute/.github/workflows/release.yml@refs/tags/$TAG"`.

### Container images

Always pull and run images by digest, from `encompute-$V-images.txt` (and
`encompute-$V-tee-images.txt` for the Confidential Space workload images).
For v0.3.3 the files contain:

```text
# encompute-0.3.3-images.txt
ghcr.io/bader82t/encompute-evaluator@sha256:a28d8c5387cf556d96cd7edb3d348b54388a4d18e7e9ad679ffca99633632ab6
ghcr.io/bader82t/encompute-control@sha256:d95e4e44b5fdf9f1853072490963e6ef3d77c718bbee0d21629a50bc681f996b
ghcr.io/bader82t/encompute-services@sha256:d27544929cb80b84c7f32a48dd9cbe5a9a5fbdb9b27ec0f3d081c55326a2b2d7
# encompute-0.3.3-tee-images.txt
ghcr.io/bader82t/encompute-confidential-space@sha256:60b1a9d19f054b87c8eea328772aaea5770ba9340c6e402032c8d904621a8225
ghcr.io/bader82t/encompute-training@sha256:29dd67b3b542abd4aa70129567dd76a1ef39232e0d649e7e99e4f7c6b8d7964a
```

Check them against the signed file you downloaded, not against this page.

```sh
cat "encompute-$V-images.txt" "encompute-$V-tee-images.txt"

while read -r IMG; do
  cosign verify "$IMG" --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null &&
  cosign verify-attestation "$IMG" --type cyclonedx \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null &&
  echo "verified: $IMG"
done < <(cat "encompute-$V-images.txt" "encompute-$V-tee-images.txt")
```

`cosign verify-attestation --type cyclonedx` checks the SBOM attached to the
image; add `| jq -r .payload | base64 -d | jq .predicate` to read it.

## 3. Attestations (GitHub build provenance)

```sh
gh attestation verify "encompute-$V-linux-x86_64.tar.gz" -R "$REPO" \
  --signer-workflow BAder82t/Encompute/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG"

while read -r IMG; do
  gh attestation verify "oci://$IMG" -R "$REPO" \
    --signer-workflow BAder82t/Encompute/.github/workflows/release.yml \
    --source-ref "refs/tags/$TAG"
done < <(cat "encompute-$V-images.txt" "encompute-$V-tee-images.txt")
```

The output names the commit, the workflow run and the runner. The commit
must be the one the tag points to:

```sh
git ls-remote https://github.com/BAder82t/Encompute.git "refs/tags/$TAG"
```

Attestations can also be verified offline with a downloaded trust root
(`gh attestation trusted-root` and `--custom-trusted-root`); see
`gh attestation verify --help`.

## What the SBOMs let you check

Each `*.cdx.json` lists every Rust crate an artifact contains (with its
license), the OpenFHE version and commit it links, and, for the wheel, the
pinned versions of the optional Python dependencies. For example, that no
research-only TFHE-rs component is present (Encompute's commercial builds
never contain it):

```sh
for s in *.cdx.json; do
  jq -r '.components[].name' "$s" | grep -Ei '^(tfhe|concrete|zama)' && echo "FOUND in $s"
done; echo "checked"
jq -r '.components[] | select(.name=="OpenFHE") | "\(.name) \(.version) \(.properties[]? | select(.name=="encompute:vcs-commit") | .value)"' \
  "encompute-$V-linux-x86_64.encompute-evaluator.cdx.json"
```

The `hashes` of an SBOM's `metadata.component` is the SHA-256 of the file it
describes.

## The Linux binaries are the ones the release check reproduced

In v0.3.3, before it signs anything, the release workflow compares the SHA-256 of the
three binaries inside `encompute-$V-linux-x86_64.tar.gz` with the digests the
release check recorded for the binaries it built twice and found
byte-identical (`scripts/release/compare-shipped-digests.sh`). Any mismatch,
missing or extra binary, or empty digest stops the workflow, so a signed
Linux tarball holds the reproduced binaries. The macOS binaries and the
wheels are not covered by this comparison (docs/release-process.md,
"Reproducibility").

## Reproducing a binary (optional)

The Rust binaries are built reproducibly: the same commit, toolchain and
OpenFHE build give the same bytes (docs/release-process.md,
"Reproducibility"). On Ubuntu 24.04 x86_64:

The commands below use the scripts of the tag you check out, so they match
that release (the unreleased `main` does not have all of them).

```sh
git clone --branch "$TAG" https://github.com/BAder82t/Encompute.git && cd Encompute
./scripts/install-openfhe.sh
# The shipping build: it resolves OPENFHE_ROOT (default .deps/openfhe) before
# it sources scripts/release/env.sh, then runs cargo build --release --locked.
scripts/release/build-release-binaries.sh "$PWD/target"
sha256sum target/release/encompute target/release/encompute-control
tar -xzf "../encompute-$V/encompute-$V-linux-x86_64.tar.gz" -O "encompute-$V-linux-x86_64/encompute" | sha256sum
```

`encompute-control` (no OpenFHE) is expected to match exactly (every release
builds twice in clean directories to check this). The CLI and the
evaluator link OpenFHE statically; they match when the OpenFHE library was
built with the same compiler (the runner's GCC), which is the known source
of variation.

## If a check fails

Do not use the files. Report it privately as described in
[SECURITY.md](../SECURITY.md), with the command and its output.
