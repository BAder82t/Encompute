# Secure aggregation

Several parties contribute private vectors; only the aggregate is released.

Several parties contribute private vectors; only the aggregate is released,
and only if enough parties took part. An `aggregate_only` asset
can reach its recipient only through this boundary.

```python
from encompute import Party, Tensor, asset, secret, secure_aggregate

coordinator = Party("coordinator")
a, b, c = (asset(f"gradient-{x}", owner=Party(f"hospital-{x}"), readers=[coordinator],
                 purposes=["disease-training"], kind="gradient", release="aggregate_only")
           for x in "abc")

@encompute.compile(purpose="disease-training")
def fedavg(ga: secret[Tensor[4096], -1.0:1.0, a], gb: secret[Tensor[4096], -1.0:1.0, b],
           gc: secret[Tensor[4096], -1.0:1.0, c]):
    return secure_aggregate(ga + gb + gc, to=coordinator, minimum=3, colluding=2,
                            clip=(-1, 1), scale=65536, modulus_bits=32)
```

```sh
encompute aggregate serve fedavg.encompute --parties parties.json --key coordinator.key
encompute aggregate join fedavg.encompute --parties parties.json --coordinator URL \
    --party hospital-a --key a.key --values gradient-a.json --state a.round
```

The protocol is Bonawitz et al.'s secure aggregation (malicious-coordinator
variant): the coordinator sees masked vectors only, even if it colludes
with up to the declared `colluding` parties; dropouts are tolerated down to
the threshold. Every party's message is signed and bound to its round;
the coordinator's own broadcasts are not signed, and its signed aggregation
receipt binds the round's outcome. Quantization is explicit and checked for
overflow at compile time. `--state` records each round a party joins; a
failed round is not rejoined, but replaced by a new one. Secure
aggregation hides contributions, not what the aggregate reveals: that needs
differential privacy.
