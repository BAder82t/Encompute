# Differential privacy

Budgets, mechanisms and the privacy ledger.

Secure aggregation hides each party's contribution; differential privacy
limits what the released aggregates reveal, across every round.
Budgets belong to assets; the compiler finds every release of a budgeted
asset and requires a mechanism; the runtime charges each release to a
tamper-evident ledger and refuses releases over budget.

```python
grads = [asset(f"gradient-{x}", owner=h, readers=[coordinator], kind="gradient",
               release="aggregate_only", privacy="strong", unit="patient")
         for x, h in zip("abc", hospitals)]
...
    return secure_aggregate(ga + gb + gc, to=coordinator, minimum=3, colluding=2,
                            clip=(-1, 1), scale=4096, modulus_bits=40, privacy="strong")
```

`encompute privacy explain` shows each budget, what one release costs and
how many releases it affords; `encompute privacy budget --ledger DIR` shows
what has been spent. A level such as `"strong"` uses twice its listed noise
for a record, patient, user or device budget, because only each party's
whole contribution is clipped; `privacy explain` shows it as
`preset=strong, sensitivity_factor=2, effective_noise_multiplier=12 (2x preset 6.0)`.
Each layer answers one question: FHE/MPC keeps the
computation confidential, secure aggregation hides contributions,
differential privacy bounds what outputs reveal, attestation says which
workload ran, and execution proofs say it computed correctly.
