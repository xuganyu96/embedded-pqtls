# Add signature scheme
## Load private key and certificates
`ssl->options.sigAlgo` is decided by the key type of the certificate.

## Match suite
Client advertises its supported signature algorithms in `ClientHello`. If the set of signature algorithms listed in `ClientHello` does not match server's configuration, then server will abort the handshake.

On the client side the list of supported signature algorithms are added at initialization via `InitSuitesHashSigAlgo`, then copied to the `signature_algorithms` extension in the following call stack:
- `SendTls13ClientHello`
- `TLSX_PopulateExtensions`
- `TLSX_SetSignatureAlgorithms`

For post-quantum digital signatures, call `AddSuiteHashSigAlgo` with `no_mac`, need to modify `AddSuiteHashSigAlgo`, which requires defining the two bytes for SignatureAlgorithm.

On the server side we need to modify `PickHashSigAlgo`