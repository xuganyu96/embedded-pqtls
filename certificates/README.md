# TLS server with WolfSSL

- For now it's okay to assume that the server will run on x86_64 Linux desktop, but keep in mind that for future work I might want to do a TLS server on a Pico 2 W as well
- Use CMake to directly compile WolfSSL source code as static library. Need to figure out `user_settings.h`.

## X.509 certificates for ML-KEM and ML-DSA
There are two relevant IETF drafts:
- [ML-KEM certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/)
- [ML-DSA certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/)

## Generate server certificate chain
`src/certgen.c` will generate a chain of 3 certificates (leaf-intermediate-root) and their corresponding private keys in the specified directory. The validity of the certificates can be verified in two ways:

**with openssl**: OpenSSL can be used to inspect and verify certificates:

```bash
openssl x509 -in <cert> -text -noout
openssl verify -CAfile <root.crt> -untrusted <int.crt> <chain.crt>
openssl s_server -cert <chain> -key <leaf.key> -port 8000
openssl s_client -connect host:port -CAfile <root> -verify_return_error < /dev/null
```

**with TLS server and curl**: pay special attention to the leaf certificate's common name, since `curl` will reject leaf certificate if `hostname` does not match the common name (although wildcard could work). On the server side, adding `--require-auth --auth <client-root-certificate>` will enforce mutual authentication, which correspondingly requires client to provide its certificate chain and key via `--cert <client-root-certificate> --key <client-private-key>` to curl. These arguments can be omitted if mutual authentication is not required (though server authentication is always required).

```bash
# first compile the tlsserver-mio example from rustls/rustls
./tlsserver-mio \
    --certs <server-certificate-chain> \
    --key <server-private-key> \
    --require-auth --auth <client-root-certificate> \
    --port 8000 http
curl https://<hostname>:<port> \
    --cert <client-certificate-chain> \
    --key <client-private-key> \
    --cacert <root-certificate>
```

## Build WolfSSL with user settings
I want to directly compile WolfSSL from source instead of using a system installation. A consequence of that is that I cannot configure compilation commands using `./configure`; instead, I need to specify a `user_settings.h` file. See [here](https://github.com/wolfSSL/wolfssl/tree/master/examples/configs) for example configs. Check [`user_settings_all.h`](https://raw.githubusercontent.com/wolfSSL/wolfssl/refs/heads/master/examples/configs/user_settings_all.h) for all feature flags.

```bash
# from project_root/server-wolfssl
curl https://raw.githubusercontent.com/wolfSSL/wolfssl/refs/heads/master/examples/configs/user_settings_template.h > config/user_settings.h
```


