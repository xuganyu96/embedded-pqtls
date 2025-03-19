# Setting up KEMTLS server
To set up a PQ-TLS/KEMTLS server:

```bash
git clone --recurse-submodules https://github.com/thomwiggers/kemtls-experiment.git
cd kemtls-experiment

# fix Dockerfile: change rust:1.66 to rust:1.85
# fix rustls/rustls/src/lib.rs linter errors
# fix mk-certs/encoder.py setrlimit failure, add loopback to HOSTNAMES

cd measuring
./scripts/create-experimental-setup.sh \
    "Kyber512"  \ # KEX
    "Kyber512"  \ # Leaf
    "Dilithium2" \ # Intermediate
    "Dilithium2" \ # Root
# TODO what about client auth and keycache?
# TODO: add altname so localhost works without having to use IP routing

# Certificates, keys, and binaries are stored in kemtls-experiment/measuring/bin/
cd kemtls-experiment/measuring/bin/kyber512-dilithium2-dilithium2-dilithium2/

# TODO: somehow libcrypto.so.1.1 is a dependency
./tlsserver --certs <signing|kem>.chain.crt \
    --key <signing|kem>.key \
    --port 8000 \
    http
./tlsclient --http --cafile <signing|kem>-ca.crt \
    --port 8000 <hostname>
```
