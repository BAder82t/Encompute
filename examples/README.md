# Examples

Every major Encompute capability has one runnable example: from a private
computation on one machine, to a full multi-party collaboration with
attestation, secure aggregation, differential privacy and a trust report.

Each example does three things:

- **Learn:** how to use the feature, with a `run.sh` that performs the
  whole workflow. There are no commands to copy from prose.
- **Verify:** the output shows that it works, and `expected.txt` lists the
  lines that must appear.
- **Understand:** every README says what the example protects, what it does
  **not** protect, and against whom.

## Start here

| Time | Example |
|---|---|
| 5 minutes | [01 private inference](01_ckks_private_inference/) |
| 10 minutes | [08 multi-party secure aggregation](08_secure_aggregation/) |
| 15 minutes | [11 automatic confidential planning](11_automatic_planner/) |
| Full demo | [12 confidential collaboration](12_confidential_collaboration/) |
| AI flagship | [15 confidential LoRA fine-tuning](15_confidential_lora/) |
| Patient privacy | [16 patient-level DP-SGD](16_patient_private_lora/) |
| Hugging Face | [17 Transformers + PEFT](17_huggingface_peft/) |

If you only run four, run **01 → 02 → 06 → 11**.

## All examples

| # | Example | Difficulty | Requires |
|---|---|---|---|
| 01 | [CKKS private inference](01_ckks_private_inference/) | beginner | Python SDK (OpenFHE for encrypted mode) |
| 02 | [Exact private logic](02_exact_private_logic/) | beginner | Python SDK (TFHE-rs research build for encrypted mode) |
| 03 | [Remote evaluator](03_remote_evaluator/) | beginner | two processes |
| 04 | [Execution receipts](04_execution_receipts/) | intermediate | a local evaluator |
| 05 | [Verified execution](05_verified_execution/) | advanced | the `vfhe-research` build (OpenFHE) |
| 06 | [Confidentiality policy](06_confidentiality_policy/) | beginner | default build |
| 07 | [Attested key release](07_attested_key_release/) | advanced | mock attestation; no cloud account |
| 08 | [Secure aggregation](08_secure_aggregation/) | intermediate | 4 processes |
| 09 | [Differential privacy](09_differential_privacy/) | intermediate | default build |
| 10 | [Trust graph](10_trust_graph/) | intermediate | default build |
| 11 | [Automatic planner](11_automatic_planner/) | beginner | Python SDK |
| 12 | [Full confidential collaboration](12_confidential_collaboration/) | advanced | several processes |
| 13 | [Assurance suite](13_assurance_suite/) | intermediate | `cargo build -p encompute-assurance --bins --examples` |
| 14 | [Python Project API](14_python_project_api/) | beginner | Python SDK |
| 15 | [Confidential LoRA fine-tuning](15_confidential_lora/) | advanced | Python SDK, PyTorch (CPU) |
| 16 | [Patient-level differential privacy (DP-SGD)](16_patient_private_lora/) | advanced | Python SDK, PyTorch (CPU) |
| 17 | [Hugging Face Transformers + PEFT](17_huggingface_peft/) | advanced | Python SDK, `encompute[huggingface]` (CPU; no download) |

## Learning paths

- **Beginner:** 01, 02, 06, 11.
- **Privacy engineer:** 06, 07, 08, 09, 10, 16.
- **Cryptography engineer:** 01, 02, 04, 05.
- **Platform or security engineer:** 03, 07, 10, 12, 13.
- **AI engineer:** 11, 14, 15, 16, 17.

## Running them

```sh
cargo build --bins
maturin develop -m crates/encompute-py/Cargo.toml     # Python examples
examples/run-all.sh quick
```

| Mode | Runs | Time |
|---|---|---|
| `quick` | 01 02 04 06 08 09 10 11 13 14 15 (mock and default-build examples) | about a minute |
| `standard` | quick, plus 03 07 12 16 17 (everything without a cloud account or crypto build) | about 6 minutes |
| `crypto` | 01 03 05 with OpenFHE and verified execution | needs `--features openfhe` / `vfhe-research` |
| `full` | everything this machine can run, and every attack in 12 | a few minutes |

An example that needs something this machine lacks (OpenFHE, TFHE-rs,
verified execution, PyTorch) prints `SKIPPED` and the reason instead of
failing. Examples 15 and 16 need PyTorch, and 17 also Transformers and PEFT
(`pip install 'encompute[huggingface]'`). For PyTorch alone:
`pip install torch --index-url https://download.pytorch.org/whl/cpu`.

## Every example has

- `run.sh`: the complete workflow, including the attacks. It exits non-zero
  on anything unexpected.
- `expected.txt`: lines that must appear in the output. It never lists IDs,
  timings or random values.
- `README.md`, with these sections:
  - what it demonstrates;
  - threat model;
  - architecture;
  - run it;
  - expected output;
  - try breaking it;
  - what Encompute guarantees;
  - what Encompute does **not** guarantee;
  - relevant source modules.

The shared helpers are in [lib.sh](lib.sh), and the runner is
[run-all.sh](run-all.sh).
