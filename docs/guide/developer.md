# Developer path

You want to write a program, run it on encrypted data and check the answer.

## 1. Run the starter

[Example 00](../../examples/00_hello_encrypted/) takes about five minutes
and needs only the Python package from the release. It encrypts four
numbers, scores them while encrypted, decrypts the result, and shows what
Encompute refuses to do.

## 2. Learn the two kinds of program

- **Approximate programs** work on real numbers. They use CKKS, an
  encryption scheme whose results are correct to a precision you declare.
  Start with [example 01](../../examples/01_ckks_private_inference/).
- **Exact programs** work on integers and yes/no values. They support
  comparisons and choosing between values. Start with
  [example 02](../../examples/02_exact_private_logic/).

A program uses one kind, never both. [Writing and running programs](programs.md)
lists the types, the operations, what the compiler checks, and the
backends.

## 3. Test and explain

- `model.test(cases=1000)` (or `encompute test`) compares the encrypted
  result with plain Python on many inputs.
- `model.explain()` (or `encompute explain`) shows the plan, the encryption
  parameters, the precision, and what the evaluator can see.
- Errors have stable codes: [error codes](../errors.md).

## 4. Put a network between the roles

Run the evaluator as its own process and verify its receipt:
[remote evaluation](remote-evaluation.md) and
[example 03](../../examples/03_remote_evaluator/).

## 5. Build from source

[Build, test and the command line](build.md). The released Python wheel
needs no build.

## Where next

- Several parties and rules about who may learn what:
  [confidentiality policies](confidentiality-policies.md),
  [secure aggregation](secure-aggregation.md),
  [differential privacy](differential-privacy.md), and the
  [planner](planner.md).
- Fine-tuning with PyTorch or Hugging Face:
  [confidential fine-tuning](confidential-fine-tuning.md).
- Which API names are stable: [API stability](../api-stability.md).
- All examples: [examples/](../../examples/).
