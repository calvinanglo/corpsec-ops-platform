#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Self-signed TLS certificate generator
# Generates CA + server cert for local development
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYS_VALID=825
COUNTRY="CA"
STATE="British Columbia"
LOCALITY="Vancouver"
ORG="corpsec-ops-platform"
OU="Security Operations"
CN="corpsec.local"

cd "$CERT_DIR"

if [[ -f server.crt && -f server.key ]]; then
    echo "[!] Certs already exist at $CERT_DIR. Delete them first to regenerate."
    exit 0
fi

echo "[+] Generating root CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS_VALID \
    -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG/OU=$OU/CN=corpsec-ca" \
    -out ca.crt

echo "[+] Generating server key..."
openssl genrsa -out server.key 4096

echo "[+] Generating server CSR with SANs..."
cat > server.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORG
OU = $OU
CN = $CN

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = corpsec.local
DNS.2 = *.corpsec.local
DNS.3 = wazuh-dashboard
DNS.4 = wazuh-manager
DNS.5 = thehive
DNS.6 = grafana
DNS.7 = n8n
DNS.8 = gophish
DNS.9 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new -key server.key -out server.csr -config server.cnf

echo "[+] Signing server cert with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS_VALID -sha256 \
    -extensions req_ext -extfile server.cnf

# Clean up intermediate files
rm -f server.csr server.cnf ca.srl

# Set restrictive permissions on private keys
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt

echo "[+] Done. Generated:"
ls -la ca.crt ca.key server.crt server.key
echo ""
echo "[!] On Windows hosts, add to hosts file (Run as Administrator):"
echo "    echo 127.0.0.1 corpsec.local >> C:\\Windows\\System32\\drivers\\etc\\hosts"
echo ""
echo "[!] Optional — trust the CA in your browser by importing ca.crt"
