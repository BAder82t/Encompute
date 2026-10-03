# Institution path

You are deploying Encompute so that several organizations can compute
together without revealing their data to each other.

## 1. Understand the limits

- [Support matrix](../support-matrix.md) and
  [known limitations](../../KNOWN_LIMITATIONS.md).
- Attested key release on Google Confidential Space is experimental.
- Other TEEs (AWS Nitro, Azure, SEV-SNP, GPU TEEs) have no provider.
- One evaluator is one machine: a job never spans machines.
- Kubernetes and Helm are not provided.

## 2. See the whole flow

[Example 12](../../examples/12_confidential_collaboration/) runs a full
collaboration: attestation, secure aggregation, differential privacy and a
trust report. [Example 11](../../examples/11_automatic_planner/) shows the
planner choosing the mechanisms from your requirements.

## 3. Deploy

- [Deploying Encompute](../deployment.md): the control plane, identities
  (OIDC), jobs, customer-managed keys (OpenBao or Vault Transit), privacy
  state and backups, audit, configuration and operations.
- The first supported deployment is Docker Compose
  ([deploy/docker-compose](../../deploy/docker-compose/)). Its bundled
  OpenBao runs in development mode: use your own key service for real keys.
- [API stability](../api-stability.md): the control plane API v1 is frozen.
- [Artifact compatibility](../compatibility.md) for upgrades.

## 4. Decide the rules

- [Confidentiality policies](confidentiality-policies.md): who owns each
  asset, who may learn what, and for which purpose.
- [Secure aggregation](secure-aggregation.md) and
  [differential privacy](differential-privacy.md): release only aggregates,
  and bound what repeated releases reveal.
- [Attested key release](attested-key-release.md): keys go only to the
  approved workload.
- [Trust graph](trust-graph.md): the evidence each party can check.

## 5. Check what you run

- [Verifying a release](../verify-release.md).
- [Threat model](../threat-model.md): the conditions your deployment must
  uphold.
- [Performance](../performance.md) and [benchmarks](../benchmarks.md):
  measured on small programs; check them against your workload.

## 6. Licence and support

Encompute is AGPL-3.0-only, with commercial licences available:
[LICENSING.md](../../LICENSING.md). Security reports:
[SECURITY.md](../../SECURITY.md).
