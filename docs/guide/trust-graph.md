# Trust graph

One bundle of evidence that answers: can I trust what happened to my data?

Every mechanism leaves evidence; the trust graph joins it into one bundle
and answers one question: can I trust what happened to my data?
Owners sign approvals of the program itself, and can revoke an asset,
which lists everything derived from it.

```sh
encompute trust init step.encompute --parties parties.json
encompute trust authorize --party hospital-a --key a.key
encompute aggregate serve step.encompute ... --trust-bundle trust.json
encompute trust report --parties parties.json --coordinator-key <hex>
```

The report rebuilds the graph from the signed evidence and checks every
signature against the keys you pass, never against keys in the bundle;
what it cannot check is reported as unchecked, and then it does not say
SATISFIED.
