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

Design decisions are recorded in [docs/adr/](docs/adr/). Changes that
affect them should update or add an ADR.
