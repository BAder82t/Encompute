"""User declares requirements. Encompute chooses mechanisms.

    python planner.py [OUT_DIR]

Three hospitals train ModelCo's model on their patients. Nobody names a
mechanism: the planner picks them, or refuses. OUT_DIR receives the program,
the training and infrastructure declarations, and the plan ID, for the CLI.
"""

import json
import os
import sys

import encompute

# The only TEE on this machine is development mock attestation: it
# protects nothing, so the planner accepts it only with allow_development.
MOCK_TEE = {
    "tees": [{"tee": "mock", "provider": "mock", "gpu": True, "cloud": True}],
    "key_broker": True,
}
NO_TEE = {"tees": [], "key_broker": True}

project = encompute.Project(
    "medical-training", parties=["hospital-a", "hospital-b", "hospital-c", "modelco"]
)
data = [project.data(f"patients-{x}", owner=f"hospital-{x}") for x in "abc"]
# private-model: only ModelCo reads the model; not the hospitals, not the cloud.
model = project.model("base-model", owner="modelco", policy="private-model")


def train(infrastructure, **kw):
    return project.train(model=model, data=data, privacy="strong",
                         verification="required", infrastructure=infrastructure, **kw)


def chose(stage, mechanisms, wants, label):
    assert all(w in mechanisms for w in wants), (stage, mechanisms)
    print(f"{stage:<18}-> {label}")


def between(text, start, end):
    return text[text.index(start):text.index(end)].strip()


print("== The requirements ==")
print("data       patients-a, patients-b, patients-c (private-training)")
print("model      base-model, owner modelco (private-model: the cloud must not see it)")
print('privacy    "strong"      verification  "required"')
print("hardware   mock TEE (development only), key broker")

run = train(MOCK_TEE, allow_development=True)
steps = {s["id"]: [m["mechanism"] for m in s["mechanisms"]] for s in run.plan["steps"]}
t, agg = steps["train:patients-a"], steps["aggregate:update"]
print("\n== What Encompute chose ==")
chose("Training", t, ["confidential_compute"], "confidential compute (mock TEE)")
chose("Gradient sharing", agg, ["secure_aggregation"], "secure aggregation")
chose("Output release", agg, ["differential_privacy"], "differential privacy")
chose("Key access", t, ["attestation", "attested_key_release"],
      "attestation (attestation-gated key release)")
print()
report = run.explain()
print(between(report, "Selected mechanisms", "\nWhy"))
print("\n" + report[report.index("RESULT"):].strip())

print("\n== Take the TEE away (the cloud still must not see the model) ==")
try:
    train(NO_TEE)
    sys.exit("planned without a TEE: this is a bug")
except encompute.PlanningFailed as e:
    print(f"error[{e.code}]")
    failed = e.report
    # One step's rejected candidates; the other two steps read the same.
    block = failed[failed.index("No valid mechanism"):]
    print("\n".join(block.splitlines()[:8]))
    print("  ... (train:patients-b and train:patients-c: the same)")
    print("\n" + failed[failed.index("RESULT"):].strip())

if len(sys.argv) > 1:
    out = sys.argv[1]
    open(os.path.join(out, "train.eir"), "w").write(run.eir)
    json.dump({"model": model.id, "data": [d.id for d in data], "verified": True},
              open(os.path.join(out, "training.json"), "w"))
    json.dump(MOCK_TEE, open(os.path.join(out, "mock-tee.json"), "w"))
    json.dump(NO_TEE, open(os.path.join(out, "no-tee.json"), "w"))
    open(os.path.join(out, "plan-id"), "w").write(run.plan_id)
