# Certificates
Ready-made certificate chains. If the folder contains one name, then all certificates use that scheme. Otherwise the names always follows `root-int-leaf-client`. Each directory contains:
- Individual certificate-key pairs: `<root|int|leaf|client>.crt` and `<xxx>.key`
- `server-chain.crt` has the leaf certificate on top
- `client-chain.crt`

|key exchange group|root|int|leaf|client|
|:----|:----|:----|:----|:----|
|ML-KEM-512|ML-DSA-65|ML-DSA-65|ML-KEM-512||
|ML-KEM-512|ML-DSA-65|ML-DSA-65|ML-DSA-44||
|HQC-128|ML-DSA-65|ML-DSA-65|ML-KEM-512||
|HQC-128|ML-DSA-65|ML-DSA-65|HQC-128||