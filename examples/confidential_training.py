"""Confidential training step: the policy graph of multi-party AI (ADR-010).

    python examples/confidential_training.py
    encompute compile examples/confidential_training.py:step -o step.encompute
    encompute privacy explain step.encompute

Hospital A owns patient data; ModelCo owns the model weights. Neither may
see the other's asset. A training step derives a gradient that may only be
released as part of an aggregate (to the training coordinator), and all of
it is for the purpose "disease-training". Encompute derives every value's
policy and rejects illegal flows at compile time. Enforcement at run time
(key release, secure aggregation) comes later; this is the policy it binds.
"""

import encompute
from encompute import Party, Tensor, asset, confidential, secret

hospital = Party("hospital-a", "Hospital A")
modelco = Party("modelco", "ModelCo")
coordinator = Party("coordinator", "Training coordinator")

patients = asset(
    "patients",
    owner=hospital,
    readers=[hospital],
    purposes=["disease-training"],
    release="never",
    kind="dataset",
    derive={"gradient": ("aggregate_only", [coordinator, modelco])},
)
weights = asset(
    "weights",
    owner=modelco,
    readers=[modelco],
    purposes=["disease-training"],
    release="never",
    kind="model",
    derive={"gradient": ("aggregate_only", [coordinator])},
)


@encompute.compile(purpose="disease-training", precision=1e-2)
def step(
    x: secret[Tensor[4], -1.0:1.0, patients],
    w: secret[Tensor[4], -1.0:1.0, weights],
):
    prediction = encompute.dot(w, x)          # uses both parties' assets
    gradient = x * w                          # a toy per-feature update
    return {
        "gradient": confidential(gradient, kind="gradient", release="aggregate_only"),
        "prediction": prediction,             # sealed: nobody may learn it
    }


if __name__ == "__main__":
    print(step.privacy())

    # Rejected at compile time: the gradient straight to the coordinator.
    def leak(
        x: secret[Tensor[4], -1.0:1.0, patients],
        w: secret[Tensor[4], -1.0:1.0, weights],
    ):
        g = confidential(x * w, kind="gradient", release="aggregate_only")
        return encompute.reveal(g, to=coordinator)

    try:
        encompute.compile(leak, purpose="disease-training", precision=1e-2)
    except encompute.EncomputeError as e:
        print(f"leak rejected: {e}")
