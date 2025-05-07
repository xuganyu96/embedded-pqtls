# Pre-generated certificates
Unless otherwise specified, the chain always goes as follows (A -> B means that `A.key` signs `B.crt`):
```
root ---> int ---> leaf
  └> client

server-chain = (leaf || int || root)
client-chain = (client || root)
```

Each set of certificates are tested for both server authentication and mutual authentication:

```bash
CERTDIR="/path/to/certificates"
# server authentication only
./tls13server --certs $CERTDIR/server-chain.crt --key $CERTDIR/leaf.key 8000
./tls13client --cafile $CERTDIR/root.crt localhost 8000

# mutual authentication
./tls13server --certs $CERTDIR/server-chain.crt --key $CERTDIR/leaf.key --cafile $CERTDIR/root.crt 8000
./tls13client --cafile $CERTDIR/root.crt --certs $CERTDIR/client-chain.crt --key $CERTDIR/client.key localhost 8000
```

If sub-directories are named with a single scheme name then everything is that scheme; otherwise the subdirectory is named with schemes matching `root-int-leaf-client`.

**notes**:
- According to [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3), the maximal signature size in `CertificateVerify` allowed is `2**16 - 1` (65535). More importantly, the record layer limit of `encrypted_record` is `2**16 - 1`, and the `Certificate` message cannot be broken up in to multple records without [major modification](https://www.ietf.org/archive/id/draft-wagner-tls-keysharepqc-00.html).