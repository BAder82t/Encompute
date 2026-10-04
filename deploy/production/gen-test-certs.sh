#!/usr/bin/env bash
# LABORATORY ONLY. Generates a throwaway PKI for trying this topology on a
# laptop: three CAs (so no certificate is trusted for a purpose it was not
# made for) and the leaf certificates the topology mounts as secrets.
#
#   ./gen-test-certs.sh [DIR]          default: ./secrets (never committed)
#
#   edge-ca       signs the edge's server certificate (a public CA, in production)
#   client-ca     signs client certificates the edge accepts on its mTLS listeners
#   internal-ca   signs PostgreSQL's server and client certificates and OpenBao's
#                 server certificate
#
# In production you bring your own certificates (see docs/production-deployment.md);
# this script's CA keys never leave DIR, and nothing in DIR is committed.
set -euo pipefail
cd "$(dirname "$0")"
DIR="${1:-secrets}"
mkdir -p "$DIR"; chmod 700 "$DIR"
umask 077
DAYS="${CERT_DAYS:-30}"
cd "$DIR"

ca() { # ca NAME: a CA certificate and key, unless they exist
  [ -s "$1.crt" ] && return 0
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.ca.key" 2>/dev/null
  openssl req -x509 -new -key "$1.ca.key" -sha256 -days "$DAYS" -subj "/O=Encompute lab/CN=$1 (throwaway)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.crt"
}
leaf() { # leaf CA NAME CN USAGE SAN: a leaf certificate signed by CA (USAGE: serverAuth or clientAuth)
  local ca="$1" name="$2" cn="$3" usage="$4" san="${5:-}"
  [ -s "$name.crt" ] && return 0
  openssl ecparam -name prime256v1 -genkey -noout -out "$name.key" 2>/dev/null
  openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
  { echo "basicConstraints=CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "extendedKeyUsage=$usage"
    [ -n "$san" ] && echo "subjectAltName=$san"; true; } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.ca.key" -CAcreateserial -sha256 -days "$DAYS" \
    -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}
ca edge-ca; ca client-ca; ca internal-ca
leaf edge-ca edge edge serverAuth "DNS:localhost,DNS:encompute.test,IP:127.0.0.1,IP:::1"
leaf client-ca ops-client ops-client clientAuth
leaf internal-ca pg-server postgres serverAuth "DNS:postgres"
# The database role the control plane connects as: with clientcert=verify-full
# in pg_hba.conf the certificate's CN must equal the role name.
leaf internal-ca pg-client encompute clientAuth
leaf internal-ca bao-server openbao serverAuth "DNS:openbao,DNS:localhost,IP:127.0.0.1"
cp internal-ca.crt bao-ca.crt   # the CA that signed OpenBao's certificate
rm -f ./*.srl
chmod 644 ./*.crt ./*.key
chmod 600 ./*.ca.key
echo "wrote a throwaway PKI to $PWD (valid $DAYS days):"
ls -1 | sed 's/^/  /'
