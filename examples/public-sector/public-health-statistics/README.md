# Public health statistics (example B)

Four regional authorities each hold weekly counts of a notifiable disease
by age stratum. The ministry of health may learn only the national
aggregate, with differential-privacy noise, for the purpose
`notifiable-disease-surveillance-2027`. Run it with `./run.sh` (default
build, about a minute; synthetic data, invented authorities).

```text
region-n  region-s  region-e  region-w     the ministry
   \         |         |        /               ^
    +--- secure aggregation, minimum 3 --+      |
             the coordinator adds noise ---> the aggregate only
```

## What it shows

- **Secure aggregation with `minimum 3`.** The coordinator sees only a
  sum, and refuses a round with fewer than three authorities. Each
  authority runs its own process, key and `--state`.
- **A population and scopes.** Each authority's budget for the series
  `regional-residents-2027` is a *population* with a hard cap (epsilon 1.0
  at delta 1e-6, per patient). This project spends it through a *scope*
  the owners allocated. A release is reserved in the scope and the
  population and must fit in both; the population is authoritative.
- **Weeks 1 to 4 release; week 5 is `RELEASE DENIED` (ENC2201).** The
  fifth week would bring the population to epsilon 1.02. Nothing was
  reserved by the refused release.
- **How many sources one person spans.** The program declares
  `max_sources_per_unit 2` (a person registered in two regions): the
  sensitivity is multiplied by it, so the cost is about four times what
  one source would cost. Undeclared, a scoped release assumes all four.
- **The strata layout and "no linkage".** Every contribution names the
  digest of the six age strata; the explain output states that an
  aggregate links no records.

## Attacks that must fail

| Script | Attack | Refused by |
|---|---|---|
| `attack-below-threshold.sh` | Two of four authorities contribute | the threshold (ENC2103); nothing released or charged |
| (in `run.sh`) | Replay a week | every authority's round sequence (ENC2102) |
| `attack-restore-budget.sh` | The coordinator restores last month's ledgers | what each authority saw (ENC2202) |
| `attack-new-version.sh` | A new dataset version (new asset IDs) for a fresh budget | the population: the same scopes and populations apply (ENC2201); without scopes the round would open |
| `attack-unrelated-project.sh` | Another project with its own scopes, then one with none | the population's cap (ENC2201); no scope allocated (ENC2719) |
| `attack-raw-release.sh` | A program that releases one region's own counts | the compiler (ENC2203) |

## What it does not protect

- **The coordinator sees the sum before noise.** Differential privacy is
  central here: the coordinator adds the noise and is trusted to (in a
  real deployment it is attested; see example 12).
- **A person in more sources than declared** is charged too little. The
  declaration is the authorities' claim, part of the program every
  authority approves.
- **The file ledgers have no four-eyes approval or anchoring.** In a
  governed project the control plane does the same accounting for every
  job: two people of the owner approve a scope, and every ledger is
  checkpointed in its governance log, so a restored older ledger is
  refused. Here the allocation is one command, and only the authorities'
  own memory (their `--state` files) detects a restored ledger.
- **A coordinator that is not attested** can ignore the ledgers; every
  authority still checks the privacy receipts it is shown.
- It is not legal advice or a statement about any real programme.

## Files

| File | |
|---|---|
| `surveillance.eir` | the program: four assets, the aggregation and its mechanism |
| `surveillance-new-version.eir` | the same with new asset IDs (a new version) |
| `raw-regional-release.eir` | the program of the last attack |
| `data/` | each authority's synthetic weekly counts |
| `common.sh`, `run.sh`, `attack-*.sh`, `expected.txt` | the story, the attacks, the expected lines |

## Commands used

```text
encompute privacy population --ledger DIR --id residents-n --organization region-n \
    --series regional-residents-2027 --unit patient --epsilon 1.0 --delta 1e-6
encompute privacy scope --ledger DIR --population residents-n --id scope-n \
    --project public-health-statistics --purpose notifiable-disease-surveillance-2027 \
    --epsilon 1.0 --asset counts-n --scoping scoping.json
encompute aggregate serve surveillance.encompute --parties parties.json --scoping scoping.json \
    --key coordinator.key --ledger DIR --sequence 10
encompute aggregate join surveillance.encompute --parties parties.json --scoping scoping.json \
    --coordinator URL --party region-n --key n.key --values data/region-n.json --state n.round
encompute privacy budget --ledger DIR --asset residents-n
```
