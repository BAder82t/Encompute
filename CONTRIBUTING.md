# Contributing

Thanks for your interest in Encompute.

- **Issues** (bugs, questions, feature requests) are welcome.
- **Pull requests** from outside contributors cannot be merged yet. Encompute is
  dual-licensed (AGPL-3.0-only and commercial, see [LICENSING.md](LICENSING.md)),
  which needs a contributor license agreement. One will be published before
  external contributions open.
- **Security issues:** do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development

See the [README](README.md#build). Before sending changes:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pytest -q
```

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
affect them should update or add an ADR.
