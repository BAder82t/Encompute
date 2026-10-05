# Reference OpenBao server configuration: TLS listener, integrated (raft)
# storage, not dev mode. Used by compose.openbao.yaml for the laboratory
# run; in production run your own OpenBao or Vault and keep this as the
# shape to match (docs/production-deployment.md).
# OpenBao has dropped mlock support: disable or encrypt swap on the host.
ui            = false
api_addr      = "https://openbao:8200"
cluster_addr  = "https://openbao:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_disable     = false
  tls_cert_file   = "/run/secrets/bao-server.crt"
  tls_key_file    = "/run/secrets/bao-server.key"
  tls_min_version = "tls12"
}

telemetry {
  disable_hostname = true
}
