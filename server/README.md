# Server
The server components of this project is directly taken from [Thom Wiggers et al.](https://github.com/thomwiggers/kemtls-experiment/tree/thesis). The `build.sh` script wraps around other scripts from the upstream repository to set up the certificate files and build both example server and client binaries.

## Getting started
This setup is tested on Ubuntu 24.04 LTS x86_64.

Pre-requisites include Docker:

```bash
docker -v
Docker version 28.0.4
```

Either clone this repository or copy this directory to the remote machine.

From this `<project-root>/server` directory, source the `build.sh` script, which exports the function `setup_experiment`. The parameters to `setup_experiment` are documented in the build script.

Example command:

```bash
setup_experiment Kyber512 Dilithium2 Dilithium2 Dilithium2
cd target/kyber512-dilithium2-dilithium2-dilithium2
# run server
./tlsserver --certs signing.chain.crt --key signing.key --port 8000 http
# run client
./tlsclient --http --cafile signing-ca.crt --port 8000 localhost
```

Relevant server-side command line options
- `--certs`: the certificate chain sent by the server in the `Certificate` message. If the leaf certificate contains a signature public key, then the file name is `signing.chain.crt`, and if the leaf certificate contains a KEM public key, then the file name is `kem.chain.crt`
- `--key`: the secret key that corresponds to the public key in the leaf certificate. File name is `kem.key` or `signing.key` depending on whether leaf certificate contains a KEM or signature key.
- `--auth` and `--require-auth`: use these two arguments to require client authentication. `--auth client-ca.crt` should point to the root certificate for client authentication.
- Set `--port` to some chosen port (e.g. 8000) and set the positional argument (mode) to `http`

Relevant client-side command line options
- `--cafile`: the root certificate used to authenticate the certificate chain sent by the server.
- `--auth-key` and `--auth-certs`: use these two arguments if mutual authentication is required. `--auth-certs` contains the certificate chain that the client will send to the server, and `--auth-key` contains the corresponding secret key
- `--http`, `--port`, and positional argument `<hostname>`. Pay special attention to `<hostname>`, because hostname needs to match the common name `CN` in the certificate sent by the server.
