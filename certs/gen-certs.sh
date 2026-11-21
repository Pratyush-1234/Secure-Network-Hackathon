#!/usr/bin/env bash
# Generates a local lab CA and a TLS server certificate for the Shield Wall WAF.
# Output: certs/ca.crt, certs/ca.key, certs/server.crt, certs/server.key
# The CA is only for this lab. Never trust it outside it.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f server.crt && -f server.key && "${1:-}" != "--force" ]]; then
  echo "[certs] server.crt already exists (use --force to regenerate)"; exit 0
fi

DAYS_CA=825
DAYS_LEAF=397   # CA/B Forum maximum for publicly trusted leaf certs, a good habit even in a lab

echo "[certs] generating lab CA (ECDSA P-256)"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS_CA" \
  -subj "/C=IN/O=Shield Wall Lab/CN=Shield Wall Lab Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca.crt

echo "[certs] generating server key + CSR"
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/C=IN/O=Shield Wall Lab/CN=shieldwall.local" -out server.csr

cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:shieldwall.local,DNS:localhost,DNS:waf,IP:127.0.0.1,IP:10.66.10.10
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS_LEAF" -sha256 -extfile server.ext -out server.crt

rm -f server.csr server.ext ca.srl
# nginx inside the container runs as uid 101, so it must be able to read the key
chmod 644 ca.crt server.crt server.key
chmod 600 ca.key

openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -subject -issuer -dates -ext subjectAltName
