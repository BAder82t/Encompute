"""The Project API: declare parties, data and policies; Encompute plans the
protection mechanisms, or refuses without weakening anything.

    python examples/14_python_project_api/project_api.py
"""

import encompute


def section(report, title, until="RESULT"):
    """The lines of one section of a plan report, up to the next heading."""
    lines = report.splitlines()
    start = lines.index(title)
    end = lines.index(until, start + 1)
    return "\n".join(lines[start:end]).rstrip()


def result(report):
    lines = report.splitlines()
    return "\n".join(lines[lines.index("RESULT"):])


# 1. A private statistic over two parties' data.
project = encompute.Project("demo", parties=["alice", "bob"])
a = project.data("alice-data", owner="alice", policy="private-training")
b = project.data("bob-data", owner="bob", policy="private-training")
plan = project.plan(data=[a, b], privacy="strong")
print(plan.explain())

# 2. Training a model on both datasets needs a TEE: the model owner and each
#    data owner must not see each other's assets, and FHE cannot train.
print("\n== Training with a (development) TEE available ==")
training = encompute.Project("demo-training", parties=["alice", "bob", "modelco"])
a = training.data("alice-data", owner="alice")
b = training.data("bob-data", owner="bob")
model = training.model("base-model", owner="modelco")
mock_tee = {
    "tees": [{"tee": "mock", "provider": "mock", "cloud": True}],
    "key_broker": True,
}
run = training.train(model=model, data=[a, b], infrastructure=mock_tee,
                     allow_development=True)
print(section(run.explain(), "Selected mechanisms", "Why"))
print(result(run.explain()))

# 3. The same training where no TEE is available fails closed.
print("\n== The same training with no TEE ==")
try:
    training.train(model=model, data=[a, b])
    raise SystemExit("UNEXPECTED: a plan was produced without a TEE")
except encompute.PlanningFailed as e:
    print(f"PlanningFailed {e.code}")
    print(section(e.report, "No valid mechanism"))
    print(result(e.report))

# A mock TEE protects nothing, so it is refused unless explicitly allowed.
print("\n== The mock TEE without allow_development ==")
try:
    training.train(model=model, data=[a, b], infrastructure=mock_tee)
    raise SystemExit("UNEXPECTED: mock attestation accepted by default")
except encompute.PlanningFailed as e:
    print(f"PlanningFailed {e.code}")
    print(next(l.strip() for l in e.report.splitlines() if "mock is development-only" in l))
