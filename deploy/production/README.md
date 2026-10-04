# Reference production topology

One blessed topology, built from the existing services with configuration and
scripts only:

- an edge (Caddy) that terminates TLS, with mutual TLS on its operations and
  key-broker listeners;
- PostgreSQL that accepts only TLS and client certificates;
- an EXTERNAL OpenBao or Vault in server mode (not dev mode), reached through a
  verifying TLS sidecar;
- every secret a file, never an environment value;
- a health check on every service, a backup and restore drill, and a validation
  script that fails a misconfigured topology.

Read [docs/production-deployment.md](../../docs/production-deployment.md): the
diagram, what each component protects and trusts, the bring-up, the hardening
checklist, and what is not covered. The validation checks configuration, not
security properties.

| File | |
|---|---|
| `compose.yaml` | the topology (images pinned by digest) |
| `compose.openbao.yaml`, `config/openbao.hcl` | a reference OpenBao to try it with; yours is external |
| `init-secrets.sh`, `bootstrap-openbao.sh`, `bao-token.sh`, `protect-asset.sh` | secrets, vault policy and AppRole, the broker's token, the first protected asset |
| `backup.sh`, `restore.sh` | backup, `--verify`, restore |
| `validate.sh` | the checklist; `negative/run.sh` proves it fails a bad topology |
| `lab-up.sh`, `gen-test-certs.sh` | laboratory only: the whole runbook with throwaway certificates (`lab-up.sh down` removes it) |

```sh
./lab-up.sh                         # a laptop with Docker: throwaway certs, identity provider and OpenBao
./validate.sh                       # PASS
./negative/run.sh                   # the validator fails a misconfigured topology
../../scripts/release/backup-drill.sh --production   # destructive drill
./lab-up.sh down
```
