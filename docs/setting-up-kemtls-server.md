# Setting up KEMTLS server
Following the guide from [Thom Wiggers' Ph.D. thesis](https://github.com/thomwiggers/kemtls-experiment/tree/thesis)

## PKI setup
TLS by default requires server authentication using certificate-based public-key infrasturcture (PKI). Each certificate binds some identity (e.g. a domain name) to some cryptographic public key (typically a digital signature public key, but since we are working with KEM-based authentication, it could also be a KEM public key). To set up PKI of our own we need:

1. There needs to be some Certificate Authority (CA) that can sign other certificates. **We assume CA will always use a digital signature**, although it might be post-quantum (so OpenSSL by itself is not enough). CA exists in the form of two files: `ca-key.pem` contains the signing/private key, `ca-cert.pem` contains CA's identity and public key.
1. TODO: Intermediate certificates are optionally and so will not be considered yet
1. CA should issue server certificate in the form of `server-key.pem` and `server-cert.pem`, as well.

The original authors used [ad-hoc scripts](https://github.com/thomwiggers/mk-cert/tree/e7836bea1b59aa39a6c46c86dd477fd5653a9795) to generate and sign certificates, but I want to do better. I want to write a CLI app in Python with the following capabilities:

- `oqspki keypair --alg <algorithm> --name <name>`  
Generate raw key pair, encode using [ASN.1](https://en.wikipedia.org/wiki/ASN.1#Example), write to `name.pub.der` and `name.priv.der`. This conatins raw bytes encoding the raw bytes of the keypair and some minimal metadata such as "which algorithm it is"
- `oqspki verify --pubkey <pubkey> --privkey <privkey>`  
Verify that the keypair is legitimate
- `oqspki b64encode --in <key.der> --out <key.pem>`  
Primarily used to encode a binary key file to base-64 encoded PEM file; not sure if it is useful?
- `oqspki x509req --pubkey <pem/der> --subj "/C=Canada..." --out <CSR file>`  
Create a certificate signing request
- `oqspki x509sign `  
Issue a Certificate based on the Certificate request
- `oqspki inspect`  
Produce a human-readable summary of some keyfile