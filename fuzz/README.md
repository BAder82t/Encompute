# Fuzzing

Coverage-guided fuzz targets ([cargo-fuzz], libFuzzer) for every parser that
reads untrusted bytes. This crate is not a workspace member: it builds on
nightly with its own `Cargo.lock`.

Malformed input must never panic, abort, exhaust memory, run without bound,
overflow an integer or be accepted unsafely. A target fails on any panic
(including a failed round-trip or verification assertion), a timeout
(`-timeout`, 30 s in `run_all.sh`) or an out-of-memory input (`-rss_limit_mb`).

| Target | Parser |
|---|---|
| `eir_parse` | `.eir` program text (`encompute_ir::parse`); accepted programs print back to themselves |
| `artifact_load` | a compiled `.encompute` directory: `manifest.json` and the files it hashes (`Model::load`) |
| `envelope_decode` | ciphertext envelopes (`encompute_protocol::Envelope::decode`), also with a valid checksum appended |
| `receipt_parse` | signed execution receipts: strict parse, canonical round trip, signature check |
| `proof_parse` | execution proofs (`ENCP`): accepted proofs are byte-for-byte canonical |
| `transcript_parse` | semantic transcripts (the statement a proof proves) |
| `trust_bundle` | Trust Graph bundles: parse, edges, lineage walks, rebuild, report |
| `trust_evidence` | every Trust Graph record type `encompute trust add` reads, added to a graph |
| `policy_parse` | attestation policies, asset policies, privacy budgets, policy documents (canonical JSON) |
| `service_headers` | signed service request headers (`ServiceHeaders::from_lookup`, `verify`) |
| `message_envelope` | signed service messages (`service::open`) |
| `job_grant` | job grants (`Encompute-Job-Grant` header and JSON) |
| `sealed_artifact` | sealed checkpoints, adapters, models and datasets (`peek`, `open`, `resume`) |
| `tensor_manifest` | canonical tensor files (`ENCTENS1`) and adapter layouts |
| `privacy_ledger` | privacy ledger files and privacy receipts; costs are never NaN or negative |
| `control_api` | control-plane request bodies, role and state names, headers, bearer tokens |
| `evaluator_bodies` | evaluator HTTP bodies: programs, key envelopes, job envelopes, key IDs (mock backend) |
| `pool_frame` | the evaluator's worker frame protocol (`len u64` prefix) and job replies |
| `attestation_evidence` | attestation evidence and records (mock and Confidential Space providers) |

Multi-part inputs (`artifact_load`, `service_headers`, `privacy_ledger`) join
their parts with the line `--8<--` (see `encompute_fuzz::SEP`).

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz build -O                 # all targets
cargo +nightly fuzz run -O eir_parse         # until stopped
./run_all.sh 300                             # 5 minutes per target, as CI does
./run_all.sh 60 pool_frame envelope_decode   # some targets
```

`run_all.sh` reads the checked-in seeds in `corpus/<target>` and writes new
corpus entries, findings and logs under `work/` (or `$FUZZ_WORK`), so the
seeds stay small. It exits non-zero if any target found something.

On macOS, AddressSanitizer's runtime can hang at start-up under recent
`dyld`; `run_all.sh` therefore uses `-s none` there (Rust code is memory
safe, and panics, aborts, timeouts and OOMs are still caught). CI runs on
Linux with AddressSanitizer. Override with `FUZZ_SANITIZER=address|none`.

To reproduce or minimize a finding:

```sh
cargo +nightly fuzz run -O <target> work/artifacts/<target>/crash-...
cargo +nightly fuzz tmin -O <target> work/artifacts/<target>/crash-...
```

Then fix the parser and add the minimized input as a regression test next to
it (every fix so far has one; see "Findings").

## Seed corpus

`corpus/<target>/` holds a few valid samples per target, made with the real
encoders by `examples/gen_corpus.rs` (deterministic keys):

```sh
cd fuzz && cargo run --example gen_corpus
```

Rerun it when a format changes. It runs on stable too.

## Stable smoke tests

Each parser also has a `tests/fuzz_smoke.rs` in its crate that runs in plain
`cargo test` on stable: thousands of deterministic mutations of valid
samples (bit flips, splices, interesting integers and tokens, truncation,
random bytes; `crates/encompute-ir/tests/fuzz_support`), each input checked
for panics and a time bound, plus resource-limit tests (length prefixes near
`u32::MAX`/`u64::MAX`, deep JSON, huge arrays, truncation, invalid UTF-8,
out-of-range integers). serde_json's recursion limit (128) is on everywhere;
nothing in the workspace disables it, and no parser uses CBOR.

## Findings

Fixed, each with a regression test:

- `pool::read_frame` allocated the declared `u64` length before reading: a
  frame claiming 2^63 bytes aborted the gateway. Frames are now capped
  (`MAX_FRAME`, 8 GiB) and the buffer grows with the bytes received.
- A short worker `EXECUTE` reply panicked the gateway thread (slice out of
  bounds); now an error (`pool::split_execute_reply`).
- A privacy event or ledger entry with a sampling rate outside (0, 1)
  reached an assertion in the RDP accountant: a panic in the control plane
  request thread and in every ledger reader. Accounting now refuses it
  (ENC2204), as it does non-finite or negative costs.
- `ledger::read` loaded ledgers of any size (the locking reader already
  refused more than 64 MiB); it now applies the same limit.
- Tensor-file and adapter-layout offsets were summed unchecked (overflow).
- The Confidential Space launcher's chunked HTTP parser computed
  `size + 2` unchecked for an untrusted chunk size.
- `service::open` computed `now + skew` unchecked.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
