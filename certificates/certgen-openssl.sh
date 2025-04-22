#!/bin/bash
set -euo pipefail

# Check for argument
if [ "$#" -ne 1 ]; then
    echo "❌ Usage: $0 <working-dir>"
    exit 1
fi

WORKDIR="$1"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

SUBJ_BASE="/C=CA/ST=ON/L=Waterloo/O=University of Waterloo"

# Check for ed25519 support
if openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
    USE_ED25519=true
    echo "✅ Using ed25519 for key generation."
else
    USE_ED25519=false
    echo "⚠️ ed25519 not supported. Falling back to RSA 2048."
fi

# Subject Alt Names config
cat > san.cnf <<EOF
subjectAltName = DNS:*.eng.uwaterloo.ca, DNS:localhost, IP:127.0.0.1
EOF

# Generate key
generate_key() {
    local name=$1
    if $USE_ED25519; then
        openssl genpkey -algorithm ed25519 -out "$name.key"
    else
        openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "$name.key"
    fi
}

# Generate CSR
generate_csr() {
    local name=$1
    local cn=$2
    openssl req -new -key "$name.key" \
        -subj "$SUBJ_BASE/CN=$cn" \
        -out "$name.csr"
}

# Generate self-signed root certificate
generate_key root
openssl req -x509 -new -nodes \
    -key root.key \
    -days 3650 \
    -subj "$SUBJ_BASE/CN=University of Waterloo Root CA" \
    -out root.crt \
    -extensions v3_ca \
    -config <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[v3_ca]\nbasicConstraints=critical,CA:true,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign"))

# Intermediate
generate_key int
generate_csr int "University of Waterloo Intermediate CA"
openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial \
    -days 1825 -out int.crt \
    -extensions v3_ca \
    -extfile <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[v3_ca]\nbasicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign"))

# Leaf (server)
generate_key leaf
generate_csr leaf "leaf.eng.uwaterloo.ca"
openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial \
    -days 825 -out leaf.crt \
    -extfile <(cat /etc/ssl/openssl.cnf san.cnf \
        <(printf "\n[leaf_ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")) \
    -extensions leaf_ext

# Client
generate_key client
generate_csr client "client.eng.uwaterloo.ca"
openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial \
    -days 825 -out client.crt \
    -extfile <(cat /etc/ssl/openssl.cnf san.cnf \
        <(printf "\n[client_ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")) \
    -extensions client_ext

# Concatenate chains
cat leaf.crt int.crt root.crt > server-chain.crt
cat client.crt root.crt > client-chain.crt

# Cleanup
rm -f *.csr *.srl san.cnf

echo "✅ All keys and certificates generated successfully in the 'certs' directory."
