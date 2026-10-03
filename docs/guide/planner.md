# Planner

Declare the requirements; Encompute chooses the mechanisms, or refuses.

Declare who owns what, who must not see it, what may be released and
whether results must be verifiable; Encompute chooses the mechanisms, or
refuses.

```python
project = encompute.Project("medical-training",
                            parties=["hospital-a", "hospital-b", "modelco"])
a = project.data("patients-a", owner="hospital-a")
b = project.data("patients-b", owner="hospital-b")
model = project.model("base-model", owner="modelco")
run = project.train(model=model, data=[a, b], privacy="strong",
                    infrastructure={"tees": [{"tee": "intel-tdx",
                                              "provider": "gcp-confidential-space"}],
                                    "key_broker": True})
print(run.explain())   # requirement → mechanism → reason → evidence
```

```sh
encompute plan step.encompute -o plan.json   # or PLANNING FAILED, with reasons
encompute check step.encompute               # program, policy, privacy, plan
encompute explain step.encompute --deep      # candidates, rejections, assumptions
```

An independent validator checks every plan; its `encplan1:` ID binds
aggregation rounds (`--plan`) and the trust graph, whose report says
whether observed execution matched the plan.
