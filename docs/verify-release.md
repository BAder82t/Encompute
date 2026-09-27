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
The examples use `v0.3.0-rc.2`; replace it with the release you verify.

```sh
TAG=v0.3.0-rc.2
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
| `encompute-$V-images.txt` | the container images, by digest |
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

Always pull and run images by digest, from `encompute-$V-images.txt`:

```sh
cat "encompute-$V-images.txt"
# ghcr.io/bader82t/encompute-evaluator@sha256:...
# ghcr.io/bader82t/encompute-control@sha256:...
# ghcr.io/bader82t/encompute-services@sha256:...

while read -r IMG; do
  cosign verify "$IMG" --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null &&
  cosign verify-attestation "$IMG" --type cyclonedx \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null &&
  echo "verified: $IMG"
done < "encompute-$V-images.txt"
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
done < "encompute-$V-images.txt"
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

## Reproducing a binary (optional)

The Rust binaries are built reproducibly: the same commit, toolchain and
OpenFHE build give the same bytes (docs/release-process.md,
"Reproducibility"). On Ubuntu 24.04 x86_64:

```sh
git clone --branch "$TAG" https://github.com/BAder82t/Encompute.git && cd Encompute
./scripts/install-openfhe.sh
. scripts/release/env.sh "$PWD/target"
OPENFHE_ROOT="$PWD/.deps/openfhe" cargo build --release --locked \
  -p encompute-cli -p encompute-evaluator -p encompute-control \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
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
