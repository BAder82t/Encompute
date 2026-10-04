# Contributing

Thanks for your interest in Encompute.

- **Issues** (bugs, questions, feature requests) are welcome.
- **Pull requests** from outside contributors cannot be merged yet. Encompute is
  dual-licensed (AGPL-3.0-only and commercial, see [LICENSING.md](LICENSING.md)),
  which needs a contributor license agreement. One will be published before
  external contributions open.
- **Security issues:** do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development

See [the build guide](docs/guide/build.md). Before sending changes:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test                                   # everything except OpenFHE and TFHE-rs
pytest -q
```

With OpenFHE installed (`./scripts/install-openfhe.sh`), also run the
production build's tests:

```sh
cargo test --workspace --features encompute-runtime/openfhe,encompute-evaluator/openfhe,encompute-cli/openfhe
```

Do not use `--all-features`: it enables the research features
(`research-tfhe-rs`, `vfhe-research`) and test-only features. Test those
separately, as the build guide shows. `scripts/release-check.sh`
runs every check from a clean checkout.

A user-visible feature is done when it has an implementation, tests, docs
and a runnable example:

```text
feature + tests + docs + example = DONE
```

Add or extend an example under [examples/](examples/) with `run.sh`,
`expected.txt`, and a README that states its threat model and what it does
**not** protect. `examples/run-all.sh quick` must pass. Every security
example shows both sides: what the mechanism protects, and what it leaves
open (for example, secure aggregation hides each contribution but not what
the aggregate reveals; that needs differential privacy).

Design decisions are recorded in [docs/adr/](docs/adr/). Changes that
affect them should update or add a decision record. Refer to decision
records by file in developer documentation; in user-facing text (README,
examples, error messages), explain the reason in words instead.
