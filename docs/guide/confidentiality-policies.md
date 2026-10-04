# Confidentiality policies

Who owns each input, who may learn what, and how results may be released.

Programs can say who owns each input, who may learn what, what the
computation is for, and how results may be released; Encompute derives the
policy of every value and rejects illegal flows at compile time.

```python
from encompute import Party, asset, confidential, secret, Tensor

hospital, modelco, coordinator = Party("hospital-a"), Party("modelco"), Party("coordinator")
patients = asset("patients", owner=hospital, readers=[hospital], purposes=["disease-training"],
                 derive={"gradient": ("aggregate_only", [coordinator])})
weights = asset("weights", owner=modelco, readers=[modelco], purposes=["disease-training"],
                kind="model", derive={"gradient": ("aggregate_only", [coordinator])})

@encompute.compile(purpose="disease-training", precision=1e-2)
def step(x: secret[Tensor[4], -1.0:1.0, patients], w: secret[Tensor[4], -1.0:1.0, weights]):
    return confidential(x * w, kind="gradient", release="aggregate_only")

print(step.privacy())   # parties, assets, derived policies, flows, warnings
```

Neither owner may learn the other's asset; the gradient may leave only as
part of an aggregate, to the coordinator; revealing it directly is ENC1905.
The policy's ID is part of the execution spec, so receipts and proofs bind
it. The compiler checks these requirements; [attested key release](attested-key-release.md)
enforces who may run the program.
