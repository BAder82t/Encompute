# Reference production topology

One blessed topology, built from the existing services with configuration and
scripts only:

- an edge (Caddy) that terminates TLS, with mutual TLS on its operations and
  key-broker listeners;
- PostgreSQL that accepts only TLS and client certificates, which the control
  plane verifies itself (`sslmode=verify-full`, a client certificate);
- an EXTERNAL OpenBao or Vault in server mode (not dev mode), which the key
  broker verifies itself (`BAO_CACERT`); there are no TLS sidecars;
- every secret a file, never an environment value;
- a health check on every service, a backup and restore drill, and a validation
  script that fails a misconfigured topology.

Read [docs/production-deployment.md](../../docs/production-deployment.md): the
diagram, what each component protects and trusts, the bring-up, the hardening
checklist, and what is not covered. The validation checks configuration, not
security properties.

| File | |
|---|---|
| `compose.yaml` | the topology (images pinned by digest; the control plane and services images are required variables, see below) |
| `compose.openbao.yaml`, `config/openbao.hcl` | a reference OpenBao to try it with; yours is external |
| `init-secrets.sh`, `bootstrap-openbao.sh`, `bao-token.sh`, `protect-asset.sh` | secrets, vault policy and AppRole, the broker's token, the first protected asset |
| `backup.sh`, `restore.sh` | backup, `--verify`, restore |
| `validate.sh` | the checklist; `negative/run.sh` proves it fails a bad topology |
| `lab-up.sh`, `gen-test-certs.sh` | laboratory only: the whole runbook with throwaway certificates (`lab-up.sh down` removes it) |

The control plane and the key broker need images that contain native TLS: the
published v0.3.0 images predate it. Set `ENCOMPUTE_CONTROL_IMAGE` and
`ENCOMPUTE_SERVICES_IMAGE`, or let the laboratory build them from this checkout
with `LAB_BUILD_IMAGES=1` (heavy).

```sh
LAB_BUILD_IMAGES=1 ./lab-up.sh                         # a laptop with Docker: throwaway certs, identity provider and OpenBao
./validate.sh                       # PASS
./negative/run.sh                   # the validator fails a misconfigured topology
../../scripts/release/backup-drill.sh --production   # destructive drill
./lab-up.sh down
```
