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

**Table of Content**:
- [`ml-dsa-44-chain`](./ml-dsa-44-chain/): everything is `ML-DSA-44`
- [`ml-dsa-65-chain`](./ml-dsa-65-chain/): everything is `ML-DSA-65`
- [`ml-dsa-87-chain`](./ml-dsa-87-chain/): everything is `ML-DSA-87`
- [`ml-dsa-mix-chain`](./ml-dsa-mix-chain/): root key is `ML-DSA-87`, intermediate key is `ML-DSA-65`, leaf and client keys are `ML-DSA-44`. This is a more realistic scenario since root keys usually have longer lifespan than its children, though it might be overkill, since `github.com`'s root certificate only uses 192-bit security.