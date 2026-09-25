# Confidential federated update

Hospitals A, B and C each hold a private gradient of 4096 values, declared
`release aggregate_only`. Each hospital runs its own participant process,
and a separate coordinator process runs one secure-aggregation round
(ADR-012). The coordinator receives only the sum of the three gradients; it
never sees any single hospital's gradient.

```sh
cargo build --bin encompute
examples/confidential_federated_update/run.sh
```

The script:
1. Compiles the program and prints the aggregation boundary: the policy, the
   mechanism, and `STATUS SATISFIED`.
2. Creates an identity for each hospital and writes the consortium's
   `parties.json`.
3. Starts the coordinator and has Hospital D, which is not in the
   consortium, try to join. D is refused with `ENC2101`.
4. Runs the three hospitals as separate processes against the coordinator.
5. Checks that the aggregate equals the plain sum of the three gradients,
   to within the declared rounding bound of `3 × 0.5/65536`.
6. Verifies the signed aggregation receipt.
