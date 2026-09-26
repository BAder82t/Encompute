"""16: patient-level differential privacy for confidential fine-tuning.

The same two hospitals fine-tune the same private model twice:

1. with organization-level privacy (each hospital's whole update clipped):
   the budget bounds what the adapter reveals about one hospital;
2. with patient-level privacy (DP-SGD: each patient's gradient clipped
   inside the attested worker, patients Poisson-sampled, noise added to the
   securely aggregated sum): the budget bounds what the adapter reveals
   about any one patient.

Then it asks for more rounds than the patient budget affords, and the run
is denied before training starts.

    python finetune.py WORKDIR
"""

import sys
from pathlib import Path

import torch

import encompute
import encompute.torch as et

W = Path(sys.argv[1]) if len(sys.argv) > 1 else None
PATIENTS = 1000


def hospital(seed: int, patients: int = PATIENTS, visits: int = 2):
    """A synthetic hospital: each patient has `visits` records (token
    sequences); the label says whether most tokens are risk markers."""
    g = torch.Generator().manual_seed(seed)
    x = torch.randint(0, 64, (patients * visits, 8), generator=g)
    y = ((x < 32).float().mean(1) > 0.5).long()
    patient_ids = torch.arange(patients).repeat_interleave(visits) + 100_000 * seed
    return et.private_dataset(x, y, unit_ids=patient_ids)


def setup():
    project = encompute.Project("patient-private-lora",
                                parties=["hospital-a", "hospital-b", "modelco"],
                                purpose="disease-training")
    torch.manual_seed(0)
    base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16, classes=2)
    model = project.model("base-model", owner="modelco", policy="private-model", module=base)
    a = project.data("patients-a", owner="hospital-a", dataset=hospital(1))
    b = project.data("patients-b", owner="hospital-b", dataset=hospital(2))
    return project, model, [a, b]


# ModelCo's own public evaluation set.
x_test, y_test, _ = hospital(9, patients=500, visits=1)


def accuracy(result, adapter=None) -> float:
    return float((result.infer(x_test, adapter=adapter).argmax(1) == y_test).float().mean())


def epsilon_used(result) -> str:
    for line in result.lineage().splitlines():
        if line.startswith("gradient-patients-a"):
            return line.split("ε used")[1].strip()
    return "?"


rows = []

print("== 1. Organization-level privacy ==\n")
project, model, data = setup()
org = project.finetune(model=model, data=data, privacy="standard", verification="required",
                       config=et.LoRAConfig(rounds=2, local_steps=10, learning_rate=0.1),
                       allow_development=True, workdir=str(W / "organization") if W else None)
rows.append(("organization", "hospital", epsilon_used(org), accuracy(org, "adapter-0"),
             accuracy(org), org.satisfied, org.timings["secure_aggregation_s"] / org.rounds))
org.close()

print("\n== 2. Patient-level privacy (DP-SGD) ==\n")
project, model, data = setup()
patient = project.finetune(
    model=model, data=data,
    privacy=encompute.Privacy(unit="patient", level="strong-patient", per_example_clip=1.0),
    verification="required",
    config=et.LoRAConfig(rounds=20, batch_size=32, learning_rate=2.0),
    allow_development=True, workdir=str(W / "patient") if W else None)
rows.append(("patient (DP-SGD)", "patient", epsilon_used(patient),
             accuracy(patient, "adapter-0"), accuracy(patient), patient.satisfied,
             patient.timings["secure_aggregation_s"] / patient.rounds))
print("\n" + patient.lineage())
print("Export\n" + patient.export)
patient.close()

print("\n== 3. More rounds than the patient budget affords ==\n")
project, model, data = setup()
try:
    project.finetune(model=model, data=data, privacy="strong-patient", allow_development=True,
                     config=et.LoRAConfig(rounds=400, batch_size=32), verbose=False,
                     workdir=str(W / "over-budget") if W else None)
    print("TRAINED OVER BUDGET (a bug)")
    sys.exit(1)
except encompute.EncomputeError as e:
    print(e)
    print("No worker started, no data was read, no budget was spent.")

print("\n== Comparison ==\n")
print(f"{'Privacy':<20}{'Protects each':<15}{'ε used':<14}{'Accuracy before':<17}"
      f"{'after':<8}{'s/round':<9}Trust")
for mode, unit, eps, before, after, ok, per_round in rows:
    print(f"{mode:<20}{unit:<15}{eps:<14}{before:<17.3f}{after:<8.3f}{per_round:<9.2f}"
          f"{'SATISFIED' if ok else 'NOT SATISFIED'}")
print("\nOnly the patient-level run bounds what the adapter reveals about one patient.")
gain = rows[1][4] - rows[1][3]
print("PATIENT-LEVEL ADAPTER LEARNED" if gain > 0.1 else f"PATIENT-LEVEL ADAPTER DID NOT LEARN "
      f"({gain:+.3f})")
sys.exit(0 if all(r[5] for r in rows) and gain > 0.1 else 1)
