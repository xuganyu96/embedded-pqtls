# Server and client commands
Depending on the choice of protocols (PQ-TLS, KEMTLS, KEMTLS-PDK, w/wo mutual authentication) the commands could be different. Here are some examples:

## PQ-TLS w/ server authentication
This the canonical way to do post-quantum TLS. Server needs to load its certificate chain (concatenation of three PEM-encoded Certificate with leaf on top and root on bottom) and signing key. Client needs to load the root certificate.

Mutual authentication commands are the same as above but with client authentication required. Server need to additionally load the root certificate of the client (i.e. the Certificte Authority who signed client's leaf certificate), and the client needs to additionally load its certificate chain and private key.
```bash
# server authentication only
./tlsserver --certs signing.chain.crt --key signing.key --port 8000 http
./tlsclient --cafile signing-ca.crt --port 8000 --http --no-tickets localhost
./tlsclient --cached-certs signing.chain.crt --cafile signing-ca.crt --port 8000 --http --no-tickets localhost

# mutual authentication
./tlsserver --certs signing.chain.crt --key signing.key --require-auth --auth client-ca.crt --port 8000 http
./tlsclient --cafile signing-ca.crt --auth-certs client.crt --auth-key client.key --port 8000 --http --no-tickets localhost
```


## KEMTLS
Similar to PQ-TLS w/ server auth, but replace leaf certificate using signature with leaf certificate using KEM.
```bash
# server authentication
./tlsserver --certs kem.chain.crt --key kem.key --port 8000 http
./tlsclient --cafile kem-ca.crt --port 8000 --http --no-tickets localhost

# Add client certificate to get mutual authentications.
./tlsserver --certs kem.chain.crt --key kem.key --require-auth --auth client-ca.crt --port 8000 http
./tlsclient --cafile kem-ca.crt --auth-certs client.crt --auth-key client.key --port 8000 --http --no-tickets localhost
```

## KEMTLS-PDK 
Client needs to additionally load server's leaf certificate. [RFC 7924](https://datatracker.ietf.org/doc/html/rfc7924) specified how client can send the `CachedInformation` extension to save the server from having to send its certificate chain.
```bash
# server authentication
./tlsserver --certs kem.chain.crt --key kem.key --port 8000 http
./tlsclient --cached-certs kem.crt --cafile kem-ca.crt --port 8000 --http --no-tickets localhost

# mutual authentication
./tlsserver --certs kem.chain.crt --key kem.key --require-auth --auth client-ca.crt --port 8000 http
./tlsclient --cached-certs kem.crt --cafile kem-ca.crt --auth-certs client.crt --auth-key client.key --port 8000 --http --no-tickets localhost
```
