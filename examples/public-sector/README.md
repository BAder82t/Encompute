# Public-sector examples

Synthetic examples of confidential data collaboration between public
authorities, built on Encompute's governed projects (see
[docs/public-sector.md](../../docs/public-sector.md)). The authorities, the
data and the rules are invented. Nothing here is legal advice, a
certification or a statement that a real programme complies with any law:
Encompute enforces what the authorities decide and records the evidence; it
does not decide what is lawful.

| Example | What it shows |
|---|---|
| [`public-health-statistics/`](public-health-statistics/) | Four regional authorities release weekly notifiable-disease counts to the ministry by secure aggregation with differential privacy. The population's budget is shared across weeks, versions and projects; a week the budget cannot pay for is refused. |

Each example has a `run.sh` (the story, ending with attacks that must
fail), an `expected.txt` (lines that must appear in its output) and, where
useful, `attack-*.sh` scripts. `examples/run-all.sh` runs them with the
numbered examples.

The examples use the command line only, with file ledgers. In a governed
project the control plane does the same accounting for every job it runs,
with two people approving each scope and every ledger checkpointed in its
governance log; see [docs/api.md](../../docs/api.md).
