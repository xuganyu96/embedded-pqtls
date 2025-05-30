Next milestone: **KEM-based unilateral authentication**
- [x] Server can start
- [x] Client can start
- [x] Client can send ClientHello
- [x] Server can process ClientHello
- [x] Server can send ServerHello
- [x] Server can send Certificate
- [x] Client can process ServerHello
- [x] Server transitions to "waiting for `KemCiphertext`" after sending `Certificate`
- [x] Client can process server's Certificate
- [x] Client can send KemCiphertext
- [ ] Server can process KemCiphertext
- [ ] Server can send Finished
- [ ] Client can send Finished

# May 30, 2025

## Implement `DoKemTlsClientKemCiphertext`
The private key is loaded with `wolfSSL_CTX_UsePrivateKey_file`, we need to retrieve it.

In `SendTls13CertificateVerify` there is `DecodePrivateKey(ssl, &args->argLen)`:
- raw bytes of the keys are stored in `ssl->buffers.key->buffer`
- the parsed key is stored in `ssl->hsKey`

Copy the ciphertext from the buffers to `ssl->kemCiphertext`, then decapsulate into `ssl->kemSharedSecret`. There is no need to clean up ciphertext or shared secret: they will be cleaned up at `wolfSSL_CleanUp`. There is the need to free the key, which is allocated within this function.

Ciphertext size is consistent with key level, but the shared secret (comparing log between client and server) is inconsistent. Dumping hex reveals even the ciphertexts are different.

There are two problems I need to troubleshoot:
- [x] ciphertexts are inconsistent between client and server. This is resolved by accounting for `*inOutIdx`
- after `DoKemTlsClientKemCiphertext`, server does not exit from `ProcessReply`

# May 29, 2025
**The entrypoints of KEMTLS** for client and server respectively:
- **server**: under `wolfSSL_accept_TLSv13`, after `SendTls13Certificate` returns, if `ssl->options.haveMlKemAuth` or `ssl->options.haveHqcAuth`, then call `accept_KEMTLS` and return its return code.
- **client**: under `wolfSSL_connect_TLSv13()`, after `serverState` reaches `SERVER_CERT_COMPLETE` (i.e. `DoTls13Certificate` returns), call `connect_KEMTLS` and return whatever it returns.

Implementing `accept_KEMTLS` and `connect_KEMTLS` are the only things remaining, I think.

## Send `ClientKemCiphertext`
**When processing server certificates, allocate for key, shared secret, and ciphertext upon KEM key**. Server's public key will be stored at `ssl->peerXXXKey` (e.g. `ssl->peerDilithiumKey`). Add `peerMlKemKey` and `peerHqcKey` as attributes to `struct WOLFSSL`. `internal.c` has `FreeHandshakeResources`, which handles cleaning up allocated keys, but I could not find a place where these values are initialized.

If `args->dCert->keyOID` is `ML_KEM_LEVELxk`, then call `                                    mlkem_ret = AllocKey(ssl, DYNAMIC_TYPE_MLKEM, (void **)&ssl->peerMlKemKey);`, but how does `AllocKey` know how much space to allocate? It uses the OID sum to identify the key type and the level. Also modify `FreeKey` so dynamically allocated keys can be properly freed.

Here is Gonzalez's implementation for sending KemCiphertext, assuming that the ciphertext has already been generated at `ProcessPeerCerts`

```c
static int SendClientKemCiphertextTls13(WOLFSSL* ssl) {
    WOLFSSL_ENTER("SendClientKemCiphertextTls13");
    byte *input, *output;
    int ret, sendSz, headerSz = HANDSHAKE_HEADER_SZ, outputSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    outputSz = ssl->kemCiphertextSz + MAX_MSG_EXTRA;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;
    /* input points to begining of handshake header */
    input = output + RECORD_HEADER_SZ;
    AddTls13Headers(output, ssl->kemCiphertextSz, client_key_exchange, ssl);
    XMEMCPY(input + HANDSHAKE_HEADER_SZ, ssl->kemCiphertext, ssl->kemCiphertextSz);
    sendSz = BuildTls13Message(ssl, output, outputSz, input,
                               headerSz + ssl->kemCiphertextSz, handshake, 1, 0, 0);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;
#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName(ssl, "ClientKemCiphertext");
        if (ssl->toInfoOn) {
            AddPacketInfo(ssl, "ClientKemCiphertext", handshake, output, sendSz,
                          WRITE_PROTO, ssl->heap);
        }
#endif
    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages != 0) {
        return ret;
    }
    ret = SendBuffered(ssl);
    if (ret != 0 && ret != WANT_WRITE)
        return ret;
    WOLFSSL_LEAVE("SendClientKemCiphertextTls13", ret);
    return ret;
}
```

It is relatively straightforward to adapt it to my API.

## Server `DoKemTlsClientKemCiphertext`
I need to implement `DoKemTlsClientKemCiphertext`, where the server uses its private key to decapsulate client's `KemCiphertext`. However, before implementing and calling `DoKemTlsClientKemCiphertext`, we need to parse the record and strip the record header and the handshake header. Parsing record and extracting the inner data is done by `ProcessReply` in `internal.h`. Example usage:

```c
/* GYX: after client replies to ServerHello (or ServerHelloAgain), keep processing
 * server response (including Certificate, CertificateVerify, and server's Finish)
 * until server's Finish has been processed.
 */
while (ssl->options.serverState < SERVER_FINISHED_COMPLETE) {
if ((ssl->error = ProcessReply(ssl)) < 0) {
        WOLFSSL_ERROR(ssl->error);
        return WOLFSSL_FATAL_ERROR;
}
```

`ProcessReply` is a big function that includes parsing the record layer, decrypting opaque fragments, finding the tag, then pass the fragment to the underlying protocol. In this context it's for processing Handshake messages, thus we need to modify `DoTls13HandShakeMsg`. `DoTls13HandshakeMsg` passes the handling to `DoTls13HandShakeMsgType`

# May 28, 2025
## Add SSL state "awaiting client KemCiphertext"
Modify the state machine so that **after sending `Certificate`, if server's private key is a KEM key then enter `expectClientKemCiphertext` instead of sending `CertificateVerify`**.

```
wolfSSL Entering SendTls13Certificate
growing output buffer
wolfSSL Entering BuildTls13Message
wolfSSL Entering EncryptTls13
wolfSSL Leaving BuildTls13Message, return 0
Shrinking output buffer
wolfSSL Leaving SendTls13Certificate, return 0
accept state CERT_SENT
wolfSSL Entering SendTls13CertificateVerify
growing output buffer
wolfSSL Leaving SendTls13CertificateVerify, return -173
wolfSSL error occurred, error = -173
```

`tls13.c` contains the workflow of the TLS state machine. After server calls `SendTls13Certificate`, it sets `ssl->options.acceptState` to `TLS13_CERT_SENT`, and later in the switch block if the state is `TLS13_CERT_SENT` then server will call `SentTls13CertificateVerify`. There are two ways to mod this:
- after `SendTls13Certificate`, depending on the private key type, set `acceptState` to a new state such as `KEMTLS_CERT_SENT`
- after `SendTls13Certificate`, set `acceptState` to `TLS13_CERT_SENT`, but under `case TLS13_CERT_SENT`, do different thing depending on the type of private key.

I like the first option. How does WolfSSL handle "waiting for peer response"? For server there are two scenarios: waiting for `ClientHello` at the beginning of the handshake, and waiting for client authentication (i.e. client's `Certificate`, `CertificateVerify`). For accept `ClientHello`:

```c
case TLS13_ACCEPT_BEGIN :
    while (ssl->options.clientState < CLIENT_HELLO_COMPLETE) {
        if ((ssl->error = ProcessReply(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
    ssl->options.acceptState = TLS13_ACCEPT_CLIENT_HELLO_DONE;
    WOLFSSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");
    if (!IsAtLeastTLSv1_3(ssl->version))
        return wolfSSL_accept(ssl);
```

There is also the section, which comes after `TLS13_CERT_VERIFY_SENT` and `TLS13_ACCEPT_FINISHED_SENT`, so this is probably where the server is waiting for client's `Certificate` and `CertificateVerify`.

```c
case TLS13_PRE_TICKET_SENT :
    while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE) {
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
    }
    ssl->options.acceptState = TLS13_ACCEPT_FINISHED_DONE;
    WOLFSSL_MSG("accept state ACCEPT_FINISHED_DONE");
    FALL_THROUGH;
```

I need a way to know if server's private key is KEM key or signature key. This is easy since previously I've left `ssl->options.haveMlKemKey` and `ssl->options.haveHqcKey`.

Ran into an unexpected behavior:

```c
case CERT_REQ_SENT:
    /* send Certificate */
    if (ssl->options.haveMlKemAuth || ssl->options.haveHqcAuth) {
        ssl->options.acceptState = KEMTLS_CERT_SENT;
        WOLFSSL_MSG("accept state KEMTLS_CERT_SENT");
    } else {
        ssl->options.acceptState = TLS13_CERT_SENT;
        WOLFSSL_MSG("accept state TLS13_CERT_SENT");
    }
    FALL_THROUGH;

case KEMTLS_CERT_SENT :
    WOLFSSL_MSG("Need to implement DoKemTlsClientKemCiphertext");
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return WOLFSSL_FATAL_ERROR;

case TLS13_CERT_SENT :
    /* send CertificateVerify */
```

Even if `acceptState` is assigned `TLS13_CERT_SENT`, the code will still go through `KEMTLS_CERT_SENT`. I don't have an elegant way to work around this within `wolfSSL_accept_TLSv13`; this is only going to get worse if I want to implement PDK later. Instead, I want to try the following idea:
1. create another method for instantiating with `ctx = wolfSSL_CTX_new(KEMTLS_client_method());`
1. since TLS 1.3 actually uses extension `supported_versions` to specify TLS version, we can extend this extension so client sends a different code to indicate that it wants to do KEMTLS handshake
1. server will process `ClientHello.extensions.supported_versions`: if the supported version is TLS 1.3 then call `wolfSSL_accept_TLSv13`, else call `accept_KEMTLS`

Client calls `wolfSSL_connect`, where if `ssl->options.tls1_3`, then returns `wolfSSL_connect_TLSv13()` (this also mirrors the server calls `wolfSSL_accept_TLSv13()`!). This means the roadmap becomes:
- implement a way so that `ssl->options.kemtls` is set to true on the client side
- implement `wolfSSL_connect_KEMTLS()`
- implement `wolfSSL_accept_KEMTLS()`

On a second thought maybe this is too ambitious. Let's keep working within the framework of a TLSv13 handshake.
- under `wolfSSL_accept_TLSv13()` (server side), if server's private keys are KEM keys (`ssl->options.haveMlKemUath || ssl->options.haveHqcAuth`) then call `accept_KEMTLS` and directly return its output

Hijacking client side is not as easy. Here is the relevant part under `wolfSSL_connect_TLSv13()`:

```c
case HELLO_AGAIN_REPLY:
    while (ssl->options.serverState < SERVER_FINISHED_COMPLETE) {
        if ((ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
        }
    }
    ssl->options.connectState = FIRST_REPLY_DONE;
    WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
    FALL_THROUGH;
```

I first need to break it up into two steps. Instead of going straight to `SERVER_FINISHED_COMPLETE`, client first needs to go to `SERVER_CERT_COMPLETE`, then check if the leaf certificate has KEM key. If yes, then hijack with `connect_KEMTLS`; if no, then proceed as normal. After the break-up:

```c
case HELLO_AGAIN_REPLY:
    while (ssl->options.serverState < SERVER_CERT_COMPLETE) {
        if ((ssl->error = ProcessReply(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
        }

    }
    /* GYX: DoTls13Certificate happened before this line so we can check
        * some flag and let connect_KEMTLS() hijack the control flow */
    WOLFSSL_MSG("serverState is at SERVER_CERT_COMPLETE");
    if (ssl->options.haveMlKemAuth || ssl->options.haveHqcAuth) {
        /* GYX: DoTls13Certificate needs to set haveMlKemAuth or haveHqcAuth */
        ssl->error = connect_KEMTLS(ssl);
        if (ssl->error != 0) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        } else {
            return WOLFSSL_SUCCESS;
        }
    }

    while (ssl->options.serverState < SERVER_FINISHED_COMPLETE) {
        if ((ssl->error = ProcessReply(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    ssl->options.connectState = FIRST_REPLY_DONE;
    WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
    FALL_THROUGH;
```

# May 27, 2025
Not quite done with `ssl_load.c`: **server cannot load certificate chain whose leaf is a KEM certificate**. The first fix is to modify `static int GetCertKey` from `asn.c` to handle `case ML_KEM_LEVEL1k` and variants. Not sure what `StoreKey` does but let's just roll with it for now. After that the server loading certificate chain passes, but there is a loggging message "Cert key not supported", reported from `wolfssl_set_have_from_key_oid`. This function sets some flags such as `ssl->options.haveDilithiumSig`, so I made similar flags `haveMlKemAuth` and `haveHqcAuth`. There is also a minimum public key size check in `ProcessBufferCertPublicKey`.

At [wolfssl@021a7f6], server can load certificate chain and leaf key containing ml-kem key. I can now run server and client pair.

```bash
# focus on unilateral authentication for now
./tls13server --debug --certs certs/server-chain.crt --key certs/leaf.key 8000
./tls13client --cafile certs/root.crt localhost 8000
```

Server debugging log will complain:

```
wolfSSL Entering DoTls13ClientHello
Supported Versions extension received
Adding signature algorithms extension
Key Share extension received
TLSX_KeyShare_HandlePQCleanMlKemKeyServer: level set to 1
Skipping Supported Versions - already processed
Signature Algorithms extension received
Supported Groups extension received
wolfSSL Entering MatchSuite
wolfSSL Entering VerifyServerSuite
Requires AEAD
Verified suite validity
Unsupported cipher suite, ClientHello 1.3
wolfSSL Leaving DoTls13ClientHello, return -501
```

The error message "Unsupported cipher suite, ClientHello 1.3" is raised in `DoTls13ClientHello` if `MatchSuite` returns error code. `MatchSuite_ex` returned 0. The actual problem is `PickHashSigAlgo`, which returns -501 (`MATCH_SUITE_ERROR`). In other words, I need a way for client to specify `signature_algorithms`.

Client calls `TLSX_PopulateExtensions`, which calls `TLSX_SetSignatureAlgorithms` to instantiate an empty `signature_algorithms` extension and push onto the list of extensions. **`TLSX_SetSignatureAlgorithms` is not where the signature algorithms are set**. Instead, the call chain is `wolfSSL_new -> InitSSL -> InitSSL_CTX_Suites -> InitSuites_EitherSide -> InitSuites -> InitSuitesHashSigAlgo`

Modified `AddSuiteHashSigAlgo` so the 2-byte code for ML-KEM and HQC as "signature algorithm" is added. Modified `InitSuitesHashSigAlgo` so that client will send `signature_algorithms` extension including ML-KEM and HQC. Modified `DecodeSigAlg` so the 2-byte code for ML-KEM and HQC as signature algorithm correctly decode back to `enum SignatureAlgorithm` and `enum wc_MACAlgorithm`. **Now server can process `ClientHello`, send `ServerHello`, and send `Certificate`, but not `CertificateVerify`**:

```
wolfSSL Entering SendTls13Certificate
growing output buffer
wolfSSL Entering BuildTls13Message
wolfSSL Entering EncryptTls13
wolfSSL Leaving BuildTls13Message, return 0
Shrinking output buffer
wolfSSL Leaving SendTls13Certificate, return 0
accept state CERT_SENT
wolfSSL Entering SendTls13CertificateVerify
growing output buffer
wolfSSL Leaving SendTls13CertificateVerify, return -173
```

# May 26, 2025
First: `wolfssl_ctx` cannot load KEM key. `wolfSSL_CTX_use_PrivateKey_buffer` will return `-463 (WOLFSSL_BAD_FILE)` 

`wolfSSL_CTX_use_PrivateKey_buffer` calls `ProcessBuffer` with parameter `type=PRIVATEKEY_TYPE`. `ProcessBuffer` then calls `static int ProcessBufferPrivateKey`. `ProcessBufferPrivateKey` will return WOLFSSL_BAD_FILE because algId remains 0 (i.e. cannot determine algorithm id).

Modified the `.clangd` at WolfSSL source root to use another user config:

```yaml
CompileFlags:
    Add: [
        -I/REDACTED/embedded-pqtls/wolfssl,
        -I/REDACTED/embedded-pqtls/server-wolfssl/config,
        -DWOLFSSL_USER_SETTINGS,
    ]
```

I need to implement `ProcessBufferTryDecodeMlKem`, which should largely follow `ProcessBufferTryDecodeDilithium`:
- Allocate for a Dilithium key `XMALLOC(sizeof(dilithium_key), heap, DYNAMIC_TYPE_DILITHIUM)`, return MEMORY_E on error. Not sure what `DYNAMIC_TYPE_DILITHIUM` is trying to do; might be a hint for memory management.
- `wc_dilithium_init`, `dilithium_PrivateKeyDecode`. If `PrivateKeyDecode` is successful, then set `keyFormatTemp`, which should be a OidSum, then use `keyFormatTemp` to set `keyTypeTemp` (the code for `signature_algorithm`) and `keySizeTemp`; on error return `ALGO_ID_E`
- WolfSSL has a method for making sure that the loaded private meets the minimal security requirement. For example, if `WOLFSSL_CTX` is configured to require an RSA key with minimum size 2048, then WolfSSL will fail to load a 1024-bit RSA key; I think for now I can ignore this, just leave a note

Now I need to implement `wc_PQCleanMlKemKey_DerToPrivateKey`. `wc_Dilithium_PrivateKeyDecode` calls `DecodeAsymKey_Assign`, so I will do the same, and that means I need to cover the case for ml-kem in `DecodeAsymKey_Assign`.

It turns out `DecodeAsymKey_Assign` does not need extra handling. So `wc_PQCleanMlKemKey_DerToPrivateKey` just kind of works.

Now `ProcessBufferTryDecode` can call `ProcessBufferTryDecodeMlKem` can get the correct *keyFormat.

`wolfSSL_CTX_use_PrivateKey_buffer` supposedly "load a private key into SSL context" but I could not see where the private key is "loaded".
- `wolfSSL_CTX_use_PrivateKey_buffer` calls `ProcessBuffer`
- `ProcessBuffer` calls `ProcessBufferPrivateKey`
- `ProcessBufferPrivateKey` calls `ProcessBufferPrivKeyHandleDer` then `ProcessBufferTryDecode`.
    - `ProcessBufferPrivKeyHandleDer`: put the DER buffer into the SSL or the SSL context object. If the `ssl` object is not null then the DER buffer is assigned to `ssl->buffers.key`. If the `ctx` object is not null then the DER buffer is assigned to `ctx->privateKey`.
    - `ProcessBufferTryDecode` tries to decode the input DER buffer as RSA, ECC, Ed25519/448, etc. until something clicks. However, `ctx` is not modified in `ProcessBufferTryDecodeDilithium`. This method only figures out the `keyFormat` (i.e. OID sum, correspondin to the type `enum Key_Sum`), the `keyType` (i.e. the code for `enum SignatureAlgorithm`), and the `keySize` (bytes of private key). The key object created in `ProcessBufferTryDecodeDilithium` is cleared and freed at the end of the function call.

So in other words, `wolfSSL_CTX_use_PrivateKey_buffer` will assign the DER buffer, but not the decoded key object, to the ssl (or context) object. This means that when server or client needs to send `CertificateVerify`, they will need to decode the key again.
- `ssl->buffers.key` is used in `DoTls13CertificateRequest`: if client has both certificates (also stored in `ssl->buffers.certificate`) and key, then set `ssl->options.sendVerify` to `SEND_CERT`.
- `SendTls13CertificateVerify`

# May 25, 2025
Let's gather the modifications I will need to make to WolfSSL:

**ClientHello's `signature_algorithms` extension**: RFC 8446 Section 4.2.3 states 

> Clients which desire the server to authenticate itself via a certificate must send the `signature_algorithms` extension. If a server is authenticating via a certificate and the client has not sent a `signature_algorithms` extension, then the server must abort the handshake with a `missing_extension` alert.

ClientHello's `signature_algorithms` extension needs a way to specify "server should authenticate using KEM, such as ML-KEM or HQC"

**Server authentication**: in both signature-authenticated and KEM-authenticated TLS, the authentication phase begins after `ClientHello`, `ServerHello`, (and optionally `EncryptedExtension`). 

With signature-based authentication:
1. server sends `Certificate`, `CertificateVerify`, and `Finished`. Server optionally sends `CertificateRequest` if requesting client authentication
1. client processes `Certificate`, `CertificateVerify`, and `Finished`, then sends its own `Finished`. Client optionally sends `Certificate` and `CertificateVerify` if server requests client authentication.

With unilateral KEM-based authentication:
1. server sends `Certificate`.
1. client uses the KEM public key from server's `Certificate` and sends `KemCiphertext`, followed by client's `Finished`
1. server decapsulates `KemCiphertext`, then sends `Finished`

With mutual KEM-based authentication:
1. server sends `Certificate` and `CertificateRequest`
1. client processes server's `Certificate` and sends `KemCiphertext`. Client sends `Certificate`
1. server processes client's `KemCiphertext` and `Certificate` and sends `KemCiphertext`
1. client processes server's `KemCiphertext` and sends `Finished`
1. server sends `Finished`

Side notes: post-handshake authentication is a open problem for KEMTLS, though it is supported in TLS 1.3 (RFC 8446 Section 4.2.6). There is also the problem of certificate issuance: certificate signing request (CSR) also needs to be authenticated, otherwise someone who does not possess the corresponding secret key can obtain CA-certified certificates containing public keys that do not belong to them.

Big surprise: [KEMTLS vs. Post-Quantum TLS: performance on embedded systems](https://eprint.iacr.org/2022/1712.pdf) does not have PDK, does not have client authentication.

# May 24, 2025
Starting this week I am finally moving onto implementing the KEMTLS protocol. Wiggers' thesis work was built on rustls, and the embedded system work was built on WolfSSL. Although the embedded work only included the client side, and it is missing the KEMTLS-PDK works, I will still rely heavily on it. The [repository](https://git.fslab.de/rgonza2s/wolfssl-kemtls-updated) containing the modified WolfSSL is self-hosted using GitLab. I don't want to have to sign up for another GitLab account, so I will get a mirror uploaded to my personal GitHub account.

I definitely don't want to manage KEMTLS implementations on two separate codebases, nor do I want to take the time to learn how rustls works. Consequently, I will need to implement both client side and server side operations on WolfSSL. This will hopefully impress the people at WolfSSL and open doors for me later down the road.

# May 23, 2025
- [x] Refactor `MakeAnyCert` to accept `void *key` and `enum CertType key_type` instead of a hard coded set of arguments
- [x] Modify `EncodePublicKey_ex` to accept key type for PQClean ML-KEM, one-time ML-KEM, and HQC
- [x] Implement `PublicKeyToDer` for PQClean ML-KEM

What would a ML-KEM-512 public key's DER look like? Here are the components:
- The last component is a `BIT STRING`. A ml-kem-512 public key contains 800 bytes. Bit string values need one more byte to encode the offset (how many unused bits at the end of the last octet), so the value of the bit string takes 801 bytes. The length `801 = 0x0321` needs long-form encoding: `0x82 0x03 0x21`. The tag of a bit string is `0x03`. **Hence the entire bit string takes 805 bytes**.
- Another inner component is the OID. The OID will be wrapped in a sequence that contains only a single element (the OID).
    - The inner OID type needs to encode the OID `2.16.840.1.101.3.4.4.1`. `2.16` encodes as `2 * 40 + 16 = 96 = 0x60`. `840`'s binary form is `0b110_1001000`, which encodes as `0b10000110 0b01001000 = 0x86 0x48`. The rest of the integers are all less than 127 and are thus trivially encoded. The value of the OID type is thus `60:86:48:01:65:03:04:04:01`. The length is `0x09`. The tag is `0x06`. The total length of the OID type is 11 bytes.
    - The `SEQUENCE` wrapping the OID type adds a tag `0x30` and a length `0x0b`, for a **total length of 13 bytes**.
- The outermost SEQUENCE needs to capture both the bit string and the inner sequence containing the OID. The value of the outer sequence is thus 818 bytes long. The length field requires long form encoding `82:03:32`. Adds the tag `0x30`.

The final length should thus be **822** bytes.

My current implementation returns 813 bytes, and the reported OID sum is 0xffffffff. I suspect something went wrong when encoding the OID. Any `KeyToDer` method will call `SetAsymKeyDerPublic`, which calls `SetASN_Oid` with `keyType`. `SetASN_OID` is a macro that calls `OidFromId`

After adding static oid arrays to `asn.c` the length is correct. I think it is safe to assume that if the length is correct then the content it correct.

# May 22, 2025
TODO:
- [ ] Refactor `MakeAnyCert` to accept `void *key` and `enum CertType key_type` instead of a hard coded set of arguments
- [ ] Modify `EncodePublicKey_ex` to accept key type for PQClean ML-KEM, one-time ML-KEM, and HQC
- [ ] Implement `PublicKeyToDer` for PQClean ML-KEM, one-time ML-KEM, and HQC.

Found that because `WOLFSSL_OLD_OID_SUM` is NOT defined, WolfSSL's OID sum actually uses an updated kind of "XOR sum" which resolves the collision problem that the old "naive sum" runs into. For now it is safe to assume that the OID sums will not collide.

Implementing `PublicKeyToDer` and `PrivateKeyToDer` are both necessary for the KEM schemes. What would a ML-KEM public key look like? An Ed448 public key looked like this in DER:

```
 296: 2 [  67]  (2) │├┬SEQUENCE
 298: 2 [   5]  (3) ││├┬SEQUENCE
 300: 2 +   3   (4) │││└─OBJECT ID       :(0x7f8e65d4) 1.3.101.113
 305: 2 +  58   (3) ││└─BIT STRING
```

ML-KEM-512's OID is `2.16.840.1.101.3.4.4.1`, which translates in octet sequence to `96:82:48:01:65:03:04:04:01`

Initial output:

```
   0: 4 [ 809]  (0) ┌SEQUENCE
   4: 2 [   2]  (1) ├┬SEQUENCE
   6: 2 +   0   (2) │└─OBJECT ID       :(0xffffffff)
   8: 4 + 801   (1) └─BIT STRING
```

The OID sum is not correct.

# May 21, 2025
Start adding KEM certificate!

I think I only need to modify `wc_MakeCert_ex`. I should not need to modify `wc_SignCert` since KEM certificates can only be signed by digital signature. `wc_DerToPem` should also remain unchanged.

`MakeCert` calls `MakeAnyCert`. `MakeAnyCert` tries to figure out the key type, then assign the input key to the variable `void *key`; the only place `key` shows up are the two calls to `EncodePublicKey(_ex)`, once for getting the encoding size, and another to actually do the encoding. `EncodePublicKey` is only a wrapper for the various "encode public key to DER" functions. 

**How does WolfSSL encode ML-DSA/SPHINCS+/Falcon keys?** Identify the OID and the public key length, then call `SetAsymKeyDerPublic`. Here is [how OID is encoded using DER](#encoding-oid-using-der). Here is [how WolfSSL works with OID](#wolfssl-oid-sum).

**OID for ML-KEM**:
- ML-KEM-512: `2.16.840.1.101.3.4.4.1`
- ML-KEM-768: `2.16.840.1.101.3.4.4.2`
- ML-KEM-1024: `2.16.840.1.101.3.4.4.3`

explanation:

```
{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) kems(4) 3}
```

For a fun fact, under `nistAlgorithm(4)` other than `kems(4)` there is also `modules(0), aes(1), hashAlgs(2), sigAlgs(3)`.

After a quick grep it seems like ml-kem's OID's are not used at all. Recall that WolfSSL's ML-KEM has a 2x speedup against PQClean's ML-KEM, for fairness of comparison with other PQClean ports I will stick with PQClean's ports as much as possible (maybe I will want to port PQClean's ML-DSA, as well).

I will just naturally extend the OIDs:

```perl
my @mlkem_1 = ( 2, 16, 840, 1, 101, 3, 4, 4, 1 );
my @mlkem_3 = ( 2, 16, 840, 1, 101, 3, 4, 4, 2 );
my @mlkem_5 = ( 2, 16, 840, 1, 101, 3, 4, 4, 3 );
my @otmlkem_1 = ( 2, 16, 840, 1, 101, 3, 4, 4, 4 );
my @otmlkem_3 = ( 2, 16, 840, 1, 101, 3, 4, 4, 5 );
my @otmlkem_5 = ( 2, 16, 840, 1, 101, 3, 4, 4, 6 );
my @hqc_1 = ( 2, 16, 840, 1, 101, 3, 4, 4, 7 );
my @hqc_3 = ( 2, 16, 840, 1, 101, 3, 4, 4, 8 );
my @hqc_5 = ( 2, 16, 840, 1, 101, 3, 4, 4, 9 );
my @mceliece_1 = ( 2, 16, 840, 1, 101, 3, 4, 4, 10 );  # mceliece348864
```

## Encoding OID using DER
OID is a sequence of integer. For example, the OID of the [Ed448 signature algorithm](https://datatracker.ietf.org/doc/html/rfc8032) is `1.3.101.113`. Each integer encodes some information (e.g. the first `1` encodes `ISO`) but the specific meaningful is beyond the scope of this project. For now it is sufficient to know that **the first integer must be 0, 1, or 2 and the second integer must be between 0 and 39 (inclusive)**.

Each OID will be encoded into an octet sequence. The first two integers are encoded into a single octet `encoding[0] = oid[0] * 40 + oid[1]`. Each of the remaining integers is converted to base-128 encoding with each digit filling a single octet. Finally for each integer, the high bit of each digit is set except for the least significant digit, which is not set to indicate that this is the end of this integer. For example, `1.2.840.10045.2.1` (ECDSA key) is encoded as `0x2a,0x86,0x48,0xce,0x3d,0x02,0x01`
- First two integers `1.2`: `1 * 40 + 2 = 42 = 0x2a`
- Second integer `840 = 0b1101001000`, which can be broken into 7-bit chunks (starting with the least significant bits?) `110` and `1001000`. The most significant chunk `110` goes into the first octet with the high bit set, which becomes `0b10000110 = 0x86`. The least significant chunk `1001000` goes into the second octet without the high bit `0b01001000 = 0x48`. Putting the two together we get `0x86 0x48`
- Third integer `10045 = 0b10011100111101`, which breaks up to `1001110 0111101`. After adding high bit: `0b11001110 -> 0xce`, `0b00111101 -> 0x3d`
- The last two integers `2.1` are both less than 127 so they are trivially encoded

## WolfSSL OID sum
By design OID is has variable length, which makes it difficult to work with; instead, WolfSSL uses a 32-bit integer to identify each unique OID. This collection is located in `oid_sum.h`.

`oid_sum.h` is generated by running `wolfssl/scripts/asn1_oid_sum.pl` (a Perl script). To compute the OID sum, WolfSSL first converts the OID (sequence of integer) into octet array [according to DER](#encoding-oid-using-der). Then, depending on whether the preprocessor macro `WOLFSSL_OLD_OID_SUM` is set, the octet array is summed using `oid_sum` (using old OID sum) or `oid_sum_xor` (not using old OID sum). The detail of how `oid_sum` and `oid_sum_xor` will be ignored for now. Let's just use the script.

# May 20, 2025
Today's goal: refactor `certgen`, also figure out a way to validate certificate chain.

Once the keypair is generated it is ready to be exported to PEM format, so `gen_keypair` should take a pointer to a buffer.

Testing a certificate chain is probably best done using a shell script `run_local_handshake.sh <certdir>` which outputs `server.log` and `client.log`.


# May 19, 2025
Today I want to first build a test program that generates a KEM-based certificate and signs it with some digital signature. This will serve as a goal post for the "generate KEM certificate" milestone.

`kem-certgen` first generates a root certificate-key pair, then generates a leaf certificate-key pair, and finally signs the leaf certificate with the root key. The certificate and the key will be exported as PEM files and to be inspected using the `asn1` program.

After some draft implementation I've changed my mind. Instead of `kem-certgen`, I want to simply re-factor `certgen` into this:

```c
int generate_chain(int root_key_type, int int_key_type, int leaf_key_type, int client_key_type,
                   uint8_t *root_cert_pem, size_t *root_cert_len,
                   uint8_t *server_chain_pem, size_t *server_chain_len,
                   uint8_t *leaf_key_pem, size_t *leaf_key_len,
                   uint8_t *client_chain_pem, size_t *client_chain_len,
                   uint8_t *client_key_pem, size_t *client_key_len);
```

This is too many arguments. Let's group the inputs into a struct and the outputs into a struct.

```c
struct certchain_suite {
    int root_key_type;
    int int_key_type;
    int leaf_key_type;
    int client_key_type;
};
struct certchain_out {
    uint8_t *root_cert_pem;
    size_t root_cert_len;
    uint8_t *server_chain_pem;
    size_t server_chain_len;
    uint8_t *server_key_pem;
    size_t server_key_len;
    uint8_t *client_chain_pem;
    size_t client_chain_len;
    uint8_t *client_key_pem;
    size_t client_key_len;
};
int generate_chain(struct certchain_suite suite, struct certchain_out *out);
```

`xxx_key_type` is sufficient for all keypair generation routines; it might be a concern that `key_type`'s type is actually `CertType` which contains other enum members that are not "key types" (e.g. `CERT_TYPE`).

```c
int gen_keypair(void **key, enum CertType key_type);
```

There is `wc_CheckRsaKey` in `rsa.h` but it is not documented in the manual or in the source code. I will use it and trust it for now, but who knows what.

Need to change `gen_keypair` to also output the number of bytes allocated to `*key`, which is needed at cleanup for `memset`.

`gen_keypair` also needs to know the expected signature type, specifically for ECDSA, since the `key_type` is insufficient to determine which of P-256/384/521 will be used.

# May 18, 2025
Goal: modify `EncodePublicKey`, possibly also implement `PublicKeyToDer` and its various complements.

`EncodePublicKey`'s function signature [currently](https://github.com/wolfSSL/wolfssl/blob/05bc7e0d2faf494bfe5b9fb0dd1806290a116559/wolfcrypt/src/asn.c#L29995) takes 11 arguments; if I add `PQCleanMlKemKey`, `OneTimeMlKemKey`, and `PQCleanHqcKey` the number of argument will bloat to 14, which is a bad design choice. I want to refactor it into the following kind of function signature:

```c
static int EncodePublicKey(int keyType, byte *key, byte *output, int OutLen);
```

There is a curious annoyance where the indenting in `asn.c` is all messed up where I am editing (EncodePublicKey is at line 29897)
- Under the function `PemToDer`, the opening bracket does not have a matching closing bracket; the closing racket according to the indent level seems to match a for loop within the function
- This block is cursed:

```c
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    #ifdef HAVE_ECC
            else if (header == BEGIN_DSA_PRIV) {
    #else
            else if (header == BEGIN_ENC_PRIV_KEY) {
    #endif
                header = BEGIN_EDDSA_PRIV;
                footer = END_EDDSA_PRIV;
            }
#endif
```

The LSP must have gotten confused because there are two opening brackets but only one closing racket. However, after refactoring to a way that has matching brackets (see below) the indent problem still persists. At this point I think the efforts are simply not worth it.

```c
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    #ifdef HAVE_ECC
            else if (header == BEGIN_DSA_PRIV) {
                header = BEGIN_EDDSA_PRIV;
                footer = END_EDDSA_PRIV;
            }
    #else
            else if (header == BEGIN_ENC_PRIV_KEY) {
                header = BEGIN_EDDSA_PRIV;
                footer = END_EDDSA_PRIV;
            }
    #endif
#endif
```

My workaround now is to simply accept the two additional indents (8 spaces), add a color column with `set colorcolumn=79,87` and indent it back if needed.

There are two places where `EncodePublicKey` is called: `MakeAnyCert` and `MakeCertReq`. The latter is never used in my program since I will always generate and sign certificate from scratch (WolfSSL currently does not support signing a certificate request anyways), hence I will not refactor the calls in `MakeCertReq`, only `MakeAnyCert`.

`MakeAnyCert` also calls `EncodeCert`, which takes the keys as input; what are they used for?

# May 16, 2025
The next big goal is to be able to generate x509 certificate that contains a KEM key.

Need to modify `wc_MakeCert_ex` to accept more key types; `wc_SignCert_ex` can stay as it is. Need to implement `PrivateKeyToDer`, `PublicKeyToDer` for the KEMs, which differs from encoding/decoding public/secret key in that they need to contain OID information. `DerToPem` can remain as it is.

`wc_MakeCert_ex` (asn.c) calls `MakeAnyCert`, which calls 
- `EncodePublicKey`, which takes `cert->KeyType`; `EncodePublicKey` is actually called twice, first to "calculate public key encoding size", then second time to actually write the public key to some data buffer.
    - `EncodePublicKey` calls `PublicKeyToDer`. `PublicKeyToDer` should set the length field even if the output buffer is `NULL`; this is how `EncodePublicKey` is used to indicate length without actually writing any data.
- `SetASN_OID`, which takes `cert->sigType`. I don't think I need to worry about signing the leaf key as it should just be the same thing.
- `MakeAnyCert` will set `cert->bodySz` at the end, which is how `wc_SignCert_ex` knows the length of the input

# May 15, 2025
I am now quite familiar with how to [plug another KEM into WolfSSL](#how-to-add-custom-key-exchange-group). Now I want to move onto KEMTLS. [This paper](https://eprint.iacr.org/2022/1111.pdf) already formally verified the security goals of KEMTLS using 1CCA-secure KEM

## Understanding ASN.1 and DER
ASN.1 is a language for describing data structures. DER (distinguished encoding rules) is one out of many set of rules for encoding data that follow structures described by ASN.1. DER differs from other encoding rules in two ways:
- DER is a binary format, unlike XER, which uses XML
- DER is canonical: every piece of data has exactly one encoding, unlike BER, where the same piece of data can be encoded in many different ways

PEM is derived from encoding the binary DER format using base64 encoding, then adding header/footer for specifying the type of content (e.g. private key, or public key, or certificate)

ASN.1 and BER/DER encoding rules are officially documented [here](https://www.itu.int/rec/T-REC-X.690-202102-I/en). Here are some key components:

- Most data structures follow the tag-length-value format. Tag is usually a single byte. Length is encoded according to either the short format or long format (see point below). The length field encodes the number of bytes of the value.
- **Short format** length uses exactly one byte. The most-significant bit must be zero, and the remaining bits encode an unsigned integer. For example, length 38 can be encoded as `0b00100110`. **Long format** length uses at least two bytes. The first byte encodes the length of the "length value". The most significant bit must be 1, but the byte must not be `0xFFFF`. The remaining bytes encode the length. For example, length 201 is encoded as `0b10000001 0b11001001`

**Example**, a x509 certificate:

```pem
-----BEGIN CERTIFICATE-----
MIIB9TCCAaegAwIBAgIUfnAIHfyACNsT3qMEjkCxaE+YSTowBQYDK2VwMHcxCzAJ
BgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xHzAdBgNV
BAoMFlVuaXZlcnNpdHkgb2YgV2F0ZXJsb28xJzAlBgNVBAMMHlVuaXZlcnNpdHkg
b2YgV2F0ZXJsb28gUm9vdCBDQTAeFw0yNTA1MTUxNTIwNThaFw0zNTA1MTMxNTIw
NThaMHcxCzAJBgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJs
b28xHzAdBgNVBAoMFlVuaXZlcnNpdHkgb2YgV2F0ZXJsb28xJzAlBgNVBAMMHlVu
aXZlcnNpdHkgb2YgV2F0ZXJsb28gUm9vdCBDQTAqMAUGAytlcAMhAGqW0UV7atwD
8xpPqgy9sxQUkxdAq6hE8sauR2wFWVCeo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEB
MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUmiIqB2dSbgLbV18F421SlbqUWXEw
BQYDK2VwA0EA5KxaHgzzGHXRieD0i0RpSy192c82Up99clRkk6YFO9jQjWNccnjl
BgdMkY4YLqYPTmYzfAZaOfwwqf3CHneQAQ==
-----END CERTIFICATE-----
```

The data in hexadecimal format:

```
30 82 01 f5 30 82 01 a7 a0 03 02 01 02 02 14 7e 70 08 1d fc 80 08 db 13 de a3 
04 8e 40 b1 68 4f 98 49 3a 30 05 06 03 2b 65 70 30 77 31 0b 30 09 06 03 55 04 
06 13 02 43 41 31 0b 30 09 06 03 55 04 08 0c 02 4f 4e 31 11 30 0f 06 03 55 04 
07 0c 08 57 61 74 65 72 6c 6f 6f 31 1f 30 1d 06 03 55 04 0a 0c 16 55 6e 69 76 
65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 31 27 30 25 06 03 55 04 
03 0c 1e 55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 20 
52 6f 6f 74 20 43 41 30 1e 17 0d 32 35 30 35 31 35 31 35 32 30 35 38 5a 17 0d 
33 35 30 35 31 33 31 35 32 30 35 38 5a 30 77 31 0b 30 09 06 03 55 04 06 13 02 
43 41 31 0b 30 09 06 03 55 04 08 0c 02 4f 4e 31 11 30 0f 06 03 55 04 07 0c 08 
57 61 74 65 72 6c 6f 6f 31 1f 30 1d 06 03 55 04 0a 0c 16 55 6e 69 76 65 72 73 
69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 31 27 30 25 06 03 55 04 03 0c 1e 
55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 20 52 6f 6f 
74 20 43 41 30 2a 30 05 06 03 2b 65 70 03 21 00 6a 96 d1 45 7b 6a dc 03 f3 1a 
4f aa 0c bd b3 14 14 93 17 40 ab a8 44 f2 c6 ae 47 6c 05 59 50 9e a3 45 30 43 
30 12 06 03 55 1d 13 01 01 ff 04 08 30 06 01 01 ff 02 01 01 30 0e 06 03 55 1d 
0f 01 01 ff 04 04 03 02 01 06 30 1d 06 03 55 1d 0e 04 16 04 14 9a 22 2a 07 67 
52 6e 02 db 57 5f 05 e3 6d 52 95 ba 94 59 71 30 05 06 03 2b 65 70 03 41 00 e4 
ac 5a 1e 0c f3 18 75 d1 89 e0 f4 8b 44 69 4b 2d 7d d9 cf 36 52 9f 7d 72 54 64 
93 a6 05 3b d8 d0 8d 63 5c 72 78 e5 06 07 4c 91 8e 18 2e a6 0f 4e 66 33 7c 06 
5a 39 fc 30 a9 fd c2 1e 77 90 01
```

How to parse it:

- `30 82 01 f5` encodes a `SEQUENCE` whose content has 501 (0x01f5) bytes (length is encoded in long form)
    - `30 82 01 a7` encodes a `SEQUENCE` whose content has 423 (0x01a7) bytes; we can now jump ahead by 423 bytes to get to the next element
        - `a0 03 02 01 02` encodes the version of the certificate: `a0` is a context-specific (bit 8 and 7), constructed (bit 6) tag; `03` encodes the length of the value; `02` is the tag for `INTEGER`; `01` encodes the length of the integer value; `02` is the actual value. The `INTEGER 2` encodes `Version 3`
        - `02 14 7e .. 3a` encodes an integer spanning 20 (0x14) bytes. In a certificate this is the serial number
        - `03 05 06 03 2b 65 70` encodes a sequence spanning 5 bytes
            - `06` is the tag for `OBJECT IDENTIFIER` (OID) `03` encodes the length of the OID, and `2b 65 70` encodes the OID. How an OID is encoded is beyond the scope of this document, but know it identifies the Signature Algorithm `ED25519`
        - `30 77 31 ... 41` encodes a sequence spanning 119 bytes. This sequence contains the issuer information (country, state, locality, etc.)
        - `30 1e 17 ... 5a` encodes a sequence that contains the "Not Before" and "Not After" dates, both encoded as `UTCTime`
        - `30 77 31 ... 41` encodes another sequence spanning 119 bytes. This sequence contains the subject information
        - `30 2a 30 .. 9e` encodes "Subject Public Key Information"
            - `30 05 .. 70` encodes the OID indicating that the public key in this certificate is an ED25519 key
            - `03 21 .. 9e` encodes an integer that is the ED25519 public key itself
        - `a3 45 30 .. 71` uses a context-specific tag `a3` "x509 v3 extensions"
    - `30 05` encodes a `SEQUENCE` whose content has 5 bytes. This is the OID for the signature below. Everything before this sequence is the "body" of the certificate, and what the issuer signs.
    - `03 41` encodes a `BIT STRING` that spans 65 (0x41) bytes; the first content byte encodes the number of unused **bits** at the end of the value, here it is `00` which means that the value is octet-aligned. This is the signature.

```
30 82 01 f5 (SEQUENCE 501 bytes)
    30 82 01 a7 (SEQUENCE 423 bytes)
        a0 03 (VERSION 3 bytes)
            02 01 02 (INTEGER 2)
        02 14 7e 70 08 1d fc 80 08 db 13 de a3 04 8e 40 b1 68 4f 98 49 3a (Serial Number)
        30 05 06 03 2b 65 70 (Signature Algorithm)
        30 77 31 0b 30 09 06 03 55 04 06 13 02 43 41 31 0b 30 09 06 03 55 04 08 0c 02 4f 4e 31 11 30 0f 06 03 55 04 07 0c 08 57 61 74 65 72 6c 6f 6f 31 1f 30 1d 06 03 55 04 0a 0c 16 55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 31 27 30 25 06 03 55 04 03 0c 1e 55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 20 52 6f 6f 74 20 43 41 (Issuer)
        30 1e 
            17 0d 32 35 30 35 31 35 31 35 32 30 35 38 5a 
            17 0d 33 35 30 35 31 33 31 35 32 30 35 38 5a 
        30 77 31 0b 30 09 06 03 55 04 06 13 02 43 41 31 0b 30 09 06 03 55 04 08 0c 02 4f 4e 31 11 30 0f 06 03 55 04 07 0c 08 57 61 74 65 72 6c 6f 6f 31 1f 30 1d 06 03 55 04 0a 0c 16 55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 31 27 30 25 06 03 55 04 03 0c 1e 55 6e 69 76 65 72 73 69 74 79 20 6f 66 20 57 61 74 65 72 6c 6f 6f 20 52 6f 6f 74 20 43 41 
        30 2a (Subject Public Key Info)
            30 05 06 03 2b 65 70 (OID: ED25519)
            03 21 00 6a 96 d1 45 7b 6a dc 03 f3 1a 4f aa 0c bd b3 14 14 93 17 40 ab a8 44 f2 c6 ae 47 6c 05 59 50 9e (the public key)
        a3 45 30 43 30 12 06 03 55 1d 13 01 01 ff 04 08 30 06 01 01 ff 02 01 01 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 01 06 30 1d 06 03 55 1d 0e 04 16 04 14 9a 22 2a 07 67 52 6e 02 db 57 5f 05 e3 6d 52 95 ba 94 59 71 
    30 05 (SEQUENCE 5 bytes) 06 03 2b 65 70 
    03 41 (BIT STRING 65 bytes) 00 e4 ac 5a 1e 0c f3 18 75 d1 89 e0 f4 8b 44 69 4b 2d 7d d9 cf 36 52 9f 7d 72 54 64 93 a6 05 3b d8 d0 8d 63 5c 72 78 e5 06 07 4c 91 8e 18 2e a6 0f 4e 66 33 7c 06 5a 39 fc 30 a9 fd c2 1e 77 90 01
```

# May 14, 2025
Goal: finish implementing `ot_mlkem.c` and `hqc.c` usin wolfcrypt's API, then make handshake.

Finished porting PQClean's clean ML-KEM and HQC, as well as modifying ML-KEM into one-time ML-KEM.

**Benchmark (units in avg ops/sec)**

|KEM                  | lvl |keygen     |enc        |dec        |
|:--------------------|:----|----------:|----------:|----------:|
|PQCLEAN-ML-KEM-512   |  1  | 13022.143 | 10426.658 |  7797.403 |
|WC-ML-KEM-512        |  1  | 21104.418 | 21284.509 | 15008.687 |
|OT-ML-KEM-512        |  1  | 12504.825 | 10448.955 | 30138.398 |
|PQCLEAN-HQC-128      |  1  |   241.912 |   122.965 |    74.999 |
|PQCLEAN-ML-KEM-768   |  3  |  7710.161 |  6430.264 |  5171.593 |
|WC-ML-KEM-768        |  3  | 13171.116 | 12690.672 |  9464.318 |
|OT-ML-KEM-768        |  3  |  7748.179 |  6379.356 | 21648.839 |
|PQCLEAN-HQC-192      |  3  |    82.166 |    40.709 |    26.037 |
|PQCLEAN-ML-KEM-1024  |  5  |  4941.532 |  4309.488 |  3599.637 |
|WC-ML-KEM-1024       |  5  |  8326.687 |  7987.836 |  6218.592 |
|OT-ML-KEM-1024       |  5  |  4927.716 |  4279.910 | 17677.426 |
|PQCLEAN-HQC-256      |  5  |    45.094 |    22.125 |    13.898 |

Is the one-time ML-KEM too fast???

## How to add custom key exchange group
Now, the definitive guide to add a new KEM, assuming that the wolfcrypt API has already been implemented.
1. Add enum to named groups in `ssl.h`, then modify `isValidCurveGroup`, `TLSX_KeyShare_IsSupported`, and `WOLFSSL_NAMED_GROUP_IS_PQC`
1. Client needs to be able to instantiate `key_share` extension in `ClientHello`. The relevant call stack starts with `SendTls13ClientHello`, then `TLSX_PopulateExtensions`. Within `TLSX_PopulateExtensions`, the user-supplied set of key exchange groups will be matched against WolfSSL's `preferredGroup`, and if there is no match, then `ClientHello` will be sent without a `key_share` extension. **add the new named group enums to preferredGroup[]**
1. Modify `TLSX_KeyShare_IsSupported` so the added named groups are accepted; modify `WOLFSSL_NAMED_GROUP_IS_PQC` (i.e. `NamedGroupIsPqc` in `internal.c`) so the group is recognized as a PQC (more importantly that it is recognized as a KEM instead of DH)
1. Modify `TLSX_KeyShare_Use`. `TLSX_KeyShare_Use` is used in both the client and the server: the client calls it to populate `key_share` entry in ClientHello, and the server calls it to populate `key_share` entry in ServerHello. We should make all the modifications:
  - `TLSX_KeyShare_HandlePqcKeyServer`: add downstream `TLSX_KeyShare_Handle<Alg>KeyServer`
  - `TLSX_KeyShare_GenPqcKeyClient`: add downstream `TLSX_KeyShare_Gen<Alg>KeyClient`
1. After modifying `TLSX_KeyShare_Use` we should have covered both "sending ClientHello" and "sending ServerHello", now we need to cover client processing ServerHello, which is done within `TLSX_KeyShare_ProcessPqcClient`: add `TLSX_KeyShare_Process<Alg>Client`

# May 13, 2025

Goal: modify `TLSX_KeyShare_ProcessPqcClient_ex` so client can handle custom KEM in ServerHello. Start adding more KEM: HQC and OT-ML-KEM.

Again similar to `GenPqcKeyClient` and `HandlePqcKeyServer`, the first step is separating `GenPqcKeyClient` from the ML-KEM specific stuff. The call stack is as follows:

- `TLSX_KeyShare_ProcessPqcClient_ex`
- called by `TLSX_KeyShare_ProcessPqcClient`
- called by `TLSX_KeyShare_Process(ssl, kse)` if `NamedGroupIsPqc(kse->group)`. Hence `NamedGroupIsPqc` should be correctly implemented.

> here is a discrepancy I noticed, which might become problematic: in `TLSX_KeyShare_ProcessPqcClient_ex`, `kse->ke` is treated as the ciphertext based on the function call `wc_KyberKey_Decapsulate(kem, ssOutput, keyShareEntry->ke, ctSz)`, but in `HandlePqcKeyServer` the ciphertext is moved into `kse->pubKey`. `HandlePqcKeyServer` takes the encapsulation key (aka pubKey).

Ok so this discrepancy ends up not being an issue. The implementation worked and can perform handshake.

I am not sure what optimization WolfSSL used such that wolfcrypt's ML-KEM is twice as fast as the PQClean port, and I don't want to spend time troubleshooting it. Instead, I will use the PQClean ML-KEM as the default ML-KEM implementation, then make a copy to modify into one-time ML-KEM.

The $T_H$ transformation described in Figure 7 of [IACR 2021/844](https://eprint.iacr.org/2021/844.pdf) does not include "hashing public key to mitigate multitarget attack and/or making the KEM contributory, so I will not do that either". Losing contributory KEM is a meaningful loss, but losing multi-target attack mitigation is probably not a big issue since keypairs are never reused. Let's also port PQClean's HQC, this time, anything not `api.h` will be put into the source directory, and only `api.h` is put into the include directory.

# May 12, 2025

Goal: can perform key exchange using `PQCLEAN_ML_KEM_512`.

**need to figure out how to incorporate heap and devId in `wc_PQCleanMlKemKey_InitEx`**

Finished draft implementation of `KeyShare_GenPQCleanMlKemKeyClient`, but there are a few issues:

- There are conflicting macros in PQClean's ML-KEM port (e.g. `KYBER_K`; they cannot be compiled together at the same time without overwriting each other.
- Need to implement a number of missing functions such as `PubKeySize`, `PrivKeySize`, and `EncodePublicKey/EncodePrivateKey`.

The macro re-definition is definitely problematic, somehow `PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES` evaluates to 2400 instead of what is should be (1632).

```
TLSX_KeyShare_GenPQCleanMlKemKeyClient: level set to 1
TLSX_KeyShare_GenPQCleanMlKemKeyClient: priv key size 2400
                                                      ^^^^ ------> this is wrong
```

It might be a good idea to **amalgamate** all source files of a single implementation into a single source file:

- `KYBER_K`, `KYBER_ETA1`, `KYBER_ETA2`, `KYBER_POLYCOMPRESSEDBYTES`, `KYBER_POLYVECCOMPRESSEDBYTES`
- structs like `poly` and `polyvec` should not be defined in the header files
- then maybe the best way to amalgamate is to hide all non-public API in the source file and leave only the things in `api.h`

Ok there is no need to amalgamate; instead I should pay attention to only use `api.h` instead of any of the internals of PQClean's implementations.

After implementing public key size, private key size, public key encode, and private key encode, ClientHello can correctly send `key_share`. Now the server needs to process the key share:

> TLSX_KeyShare_HandlePqcKeyServer: Invalid PQC algorithm specified.

Call stack:

```
TLSX_KeyShare_HandlePqcKeyServer
- TLSX_KeyShare_Use
- TLSX_KeyShareEntry_Parse
- TLSX_KeyShare_Parse_ClientHello
- TLSX_Parse
- DoTls13ClientHello
```

Similar to `GenPqcKeyClient`, `HandlePqcKeyServer` will be refactored to call other KEM specific subroutines. Separated out WC's ML-KEM handler from `HandlePqcKeyServer`, then implemented PQClean's ML-KEM handler and the missing `DecodePublicKey` and `DecodePrivKey` for PQClean's ML-KEM. Server now reports "wolfSSL Leaving SendTls13ServerHello, return 0", indicating server correctly handled PQClean's ML-KEM key share.

# May 11, 2025

From RFC 8446 section 4.2.8: Clients MAY send an empty client_shares vector in order to request group selection from the server, at the cost of an additional round trip (see Section 4.1.4 "Hello Retry Request").

Added `PQCLEAN_ML_KEM_XXX` to `NamedGroupIsPqc` and `preferredGroup`. The next error is from the client: "Invalid Kyber algorithm specified", which comes from `TLSX_KeyShare_GenPqcKeyClient (tls.c)`.

Assume that `WOLFSSL_TLSX_PQC_MLKEM_STORE_OBJ` is not defined (otherwise the entire `KyberKey` object will be stored in memory instead of just the private key).

- `KeyShareEntry *kse` is the input; `kse->group` is the named group.
- `KyberKey kem` is allocated on the stack.
- `byte *privKey` will be allocated on the heap
- public key will also be allocated from the heap, but it will be owned by `kse->pubKey`
- When generating keypair, RNG comes from `ssl->rng`, heap comes from `ssl->heap`, and dev ID comes from `ssl->devId`
- `EncodePublicKey` writes the public key to `kse->pubKey`
- `EncodePrivateKey` writes the private key to the heap-allocated private key
- If anything goes wrong, `kem` needs to be zero'd, `kse->pubKey` and `privKey` both need to be freed
- If all goes right, the ownership of `privKey` moves to `kse->privKey`

# May 10, 2025

There is `wolfSSL_UseKeyShare(ssl, namedgroup)`, maybe it was the same abstraction for generating the `key_share` extension:

- Add NamedGroup enum member to NamedGroupIsPqc in internal.c. This is not critical
- `wolfSSL_UseKeyShare` calls `TLSX_KeyShare_Use`, but when client runs it did not call `wolfSSL_UseKeyShare`, it did not call `TLSX_KeyShareNew` either

Call chain: `SendTls13ClientHello -> TLSX_PopulateExtensions -> TLSX_KeyShare_Use not called`. There is a `preferredGroup` if `set_group` does not contain a named group that in the preferred named groups, then ClientHello will be sent without `key_share`.

Next step:

- need to add new enum member to preferredGroup, need to modify `TLSX_KeyShare_Use -> KeyShare_GenKey -> KeyShare_GenPqcKeyClient`. The last function is where `KyberKey_XXX` methods are caslled. Also need to call `EncodePublicKey`.

# May 9, 2025

- Incorporate PQClean's MLKEM into key exchange group and check if handshake works
- Troubleshoot where PQClean's ML-KEM is slower than WolfSSL's ML-KEM

`wolfSSL_CTX_set_groups` can be used to set the key exchange groups, one example is `WOLFSSL_ML_KEM_512`. I want to try adding `PQCLEAN_ML_KEM_512|768|1024`. This will be helpful for adding PQCLEAN_HQC and one-time ML-KEM later on.

**Step 1: make `wolfSSL_CTX_set_groups` return `SSL_SUCCESS`**

- Add enum members to `NamedGroups` in `ssl.h`
- Modify `isValidCurveGroup` in `ssl.c` so the new enum members are accepted
- Modify `TLSX_KeyShare_IsSupported()` in `tls.c` so the new enum members are supported

At this point the client can send ClientHello to the server, but this `ClientHello` is missing the `key_share` extension, which should contain the public key. To be able to generate the correct key share I need to do the following:

- Modify `TLSX_KeyShare_GenPqcKeyClient` so that it can handle more variety of PQC types
- Implement `EncodePublicKey` for PQCLean's ML-KEM
- Add PQClean ML-KEM to `preferredGroups` in `tls.c`
- Add PQClean ML-KEM to `NamedGroupIsPqc` in `internal.c`

These will be work for another session.

# May 8, 2025

- Cannot use Falcon/SPHINCS as leaf or client key
- Implement OT-ML-KEM

Thom Wiggers [SPHINCS+ or Falcon for leaf certificate](https://github.com/thomwiggers/kemtls-experiment/blob/thesis/measuring/scripts/experiment.py)?

## Implement OT-ML-KEM

Should I start with PQClean or WolfSSL? I will try porting PQClean's ML-KEM into WolfSSL and compare performance. If performance is comparable then I will modify PQClean's implementation into OT-ML-KEM. After a naive port, using PQClean's `fips202` instead of WolfSSL's SHA3 impl's, performance of PQClean's ML-KEM is about half of WolfSSL's:

```
PQCLEAN-ML-KEM 512     keygen     12620.479 ops/sec
ML-KEM 512             keygen     21144.999 ops/sec
PQCLEAN-ML-KEM 512      encap     10414.187 ops/sec
ML-KEM 512              encap     21359.225 ops/sec
PQCLEAN-ML-KEM 512      decap     8071.862 ops/sec
ML-KEM 512              decap     15074.601 ops/sec

PQCLEAN-ML-KEM 768     keygen     7757.303 ops/sec
ML-KEM 768             keygen     13309.165 ops/sec
PQCLEAN-ML-KEM 768      encap     6496.187 ops/sec
ML-KEM 768              encap     12791.839 ops/sec
PQCLEAN-ML-KEM 768      decap     5234.568 ops/sec
ML-KEM 768              decap     9496.753 ops/sec

PQCLEAN-ML-KEM 768     keygen     4976.169 ops/sec
ML-KEM 1024            keygen     8454.447 ops/sec
PQCLEAN-ML-KEM 768      encap     4345.426 ops/sec
ML-KEM 1024             encap     8108.103 ops/sec
PQCLEAN-ML-KEM 768      decap     3605.661 ops/sec
ML-KEM 1024             decap     6331.131 ops/sec
```

This is probably not acceptable. Without detailed profiling my blind guess is the SHA3 implementation, since at a quick glance WolfSSL's ML-KEM impl does not seem very sophisticated.

Compared Shake256 outputs and can confirm that wolfcrypt and PQClean's Shake256 are both correct:

```c
static void compare_sha3(void) {
  uint8_t input[4096] = {
      42,
  };
  uint8_t wc_output[8192];
  uint8_t pqc_output[8192];

  printf("TEST: absorb continuous 4096 bytes, squeeze continuous 8192 bytes\n");
  wc_Shake wc_shake;
  wc_InitShake256(&wc_shake, NULL, INVALID_DEVID);
  /* NOTE: absorb = update + finalize but no output */
  wc_Shake256_Update(&wc_shake, input, sizeof(input));
  wc_Shake256_Final(&wc_shake, wc_output, sizeof(wc_output));
  // wc_Shake256_Free(&wc_shake);

  shake256incctx pqc_shake;
  shake256_inc_init(&pqc_shake);
  shake256_inc_absorb(&pqc_shake, input, sizeof(input));
  shake256_inc_finalize(&pqc_shake);
  shake256_inc_squeeze(pqc_output, sizeof(pqc_output), &pqc_shake);
  // shake256_inc_ctx_release(&pqc_shake);

  if (memcmp(wc_output, pqc_output, sizeof(wc_output)) == 0) {
    printf("wolfcrypt and pqclean outputs agree\n");
  }
}
```

From WolfCrypt benchmark:

```
SHA3-224                   135 MiB took 1.033 seconds,  130.659 MiB/s
SHA3-256                   125 MiB took 1.000 seconds,  124.952 MiB/s
SHA3-384                   100 MiB took 1.041 seconds,   96.028 MiB/s
SHA3-512                    70 MiB took 1.047 seconds,   66.878 MiB/s
SHAKE128                   155 MiB took 1.029 seconds,  150.595 MiB/s
SHAKE256                   125 MiB took 1.007 seconds,  124.159 MiB/s
```

My crude 100MB test (below) took 731980 microseconds, which is `131MiB/s`, roughly equal to WolfSSL's implementation.

```c
/* Absorb some 100MB of data and squeeze */
struct timespec start, end;
uint64_t elapsed_us;

size_t large_input_len = 100 * 1000 * 1000; /* 100 million bytes */
uint8_t *large_input = malloc(large_input_len);

clock_gettime(CLOCK_MONOTONIC, &start);
shake128_inc_init(&pqc_shake128);
shake128_inc_absorb(&pqc_shake128, large_input, large_input_len);
shake128_inc_finalize(&pqc_shake128);
shake128_inc_squeeze(pqc_output, sizeof(pqc_output), &pqc_shake128);

clock_gettime(CLOCK_MONOTONIC, &end);
elapsed_us = (end.tv_sec - start.tv_sec) * 1000000L +
            (end.tv_nsec - start.tv_nsec) / 1000L;
printf("myfunc took %" PRIu64 " microseconds.\n", elapsed_us);
free(large_input);
```

# May 7, 2025

Today I want to solve three problems in decreasing priority:

1. Cannot generate CA certificate using Falcon
2. Cannot use Falcon/SPHINCS and leaf/client key
3. ML-DSA certificates intermittently fails

For tomorrow I want to implement OT-ML-KEM, which should be a fork of ML-KEM from WolfSSL.

**Generate CA certificate using Falcon-512**:

- Added `ROOT_KEY_TYPE == USE_FALCON_512` in `certgen.c`, `./certgen certs` exits successfully. `falcon512-mldsa65-mldsa44-mldsa-44` chain passes server and mutual authentication test.
- Added `ROOT_KEY_TYPE == USE_FALCON_1024`, `falcon1024-mldsa65-mldsa44-mldsa44` chain passes server/mutal authentication test.

Wait so Falcon as CA just works? Apparently yes. Yesteryday's problem is that `sphincs192` fails to run.

**Generate CA certificate with SPHINCS-192s**:
In `certgen.c` set `ROOT_KEY_TYPE == USE_SPHINCS192S`, at runtime client reprots `"Failed to make unsigned root certificate (err -134)"`. [Error code](https://www.wolfssl.com/documentation/manuals/wolfssl/appendix06.html) -134 is "setting public key error".

`PUBLIC_KEY_E` is returned by `wc_MakeCert_ex`. `wc_MakeCert_ex` calls `MakeAnyCert`. `MakeAnyCert` calls `EncodePublicKey`. `EncodePublicKey` calls `wc_Sphincs_PublicKeyToDer` in case `SPHINCS_SMALL_LEVEL3_KEY`. `wc_Sphincs_PublicKeyToDer` returned `-173 (BAD_FUNC_ARG)`.

```
lldb -- certgen certs
breakpoint set --name wc_MakeCert_ex
gui  # exit with escape
```

[`sphincs.c`](https://github.com/wolfSSL/wolfssl/blob/eae40058841f471e3b56da606d8d3ed8970b9bd4/wolfcrypt/src/sphincs.c#L327) has incorrect key level validation, hence why 128/256 works but not 192. After fixing that the `sphincs192s-mldsa65-mldsa44-mldsa44` chain works.

`sphincs192f-mldsa65-mldsa44-mldsa44` certgen is successful, but client fails to load root certificate (-148 ASN_UNKNOWN_OID_E). I found [this cursed piece of code](https://github.com/wolfSSL/wolfssl/blob/eae40058841f471e3b56da606d8d3ed8970b9bd4/wolfcrypt/src/asn.c#L6873) that might be the root cause. It is indeed the cause! Here is the snippet:

```c
// wolfcrypt/src/asn.c
#if defined(HAVE_SPHINCS)
    /* Since we are summing it up, there could be collisions...and indeed there
     * are: SPHINCS_FAST_LEVEL1 and SPHINCS_FAST_LEVEL3.
     *
     * We will look for the special case of SPHINCS_FAST_LEVEL3 and set *oid to
     * 283 instead of 281; 282 is taken.
     *
     * These hacks will hopefully disappear when new standardized OIDs appear.
     */
    if (idx + (word32)sizeof(sigSphincsFast_Level3Oid) < (word32)length &&
            XMEMCMP(&input[idx], sigSphincsFast_Level3Oid,
               sizeof(sigSphincsFast_Level3Oid)) == 0) {
        found_collision = SPHINCS_FAST_LEVEL3k;
    }
#endif /* HAVE_SPHINCS */
```

The culprit is the length check: `idx + (word32)sizeof(sigSphincsFast_Level3Oid) < (word32)length`. `idx` marks the beginning of the OID buffer, and `length` marks the length (not capacity!) of the OID buffer. This snippet intends to check if the input OID buffer's length is big enough to contain the OID buffer length of `sigSphincsFast_Level3Oid`, so the comparison should be `<=` instead of `<`. **An off-by-one error!**

After fixing that the error went away, though the server certificate chain is too large.

# May 6, 2025

Getting started with porting Falcon. First enable Falcon in the benchmarking by defining the macro `HAVE_FALCON` in `user_settings.h`. `benchmark_test(NULL)` will then include `bench_falconKeySign()`, which will print failure message if signing fails.

There is no need to expose the seed from the PQClean implementation. Porting Falcon from PQClean is the same as porting SPHINCS+: copying over the source files, then sort out the header problems, substituting `random.h` with `WC_RNG` but retaining `fips202.h` (just for now).

**Bug with Falcon port:** after porting, benchmarking works, but `certgen.c`'s generated `leaf.key` fails to load. Using Falcon-1024 as intermediate key also causes TLS client to fail to verify signature. This might have something to do with the ovservation that Falcon signatures are variable sized? Maybe I should have ported Falcon-padded.

Need to check if SPHINCS and Falcon can be used for certificate generation, but `certgen.c` is such sphaghetti code TAT.

**Try generating SPHINCS chain**: root and intermediate keys can use any variant; not sure about the performance implications of using SPHINCS for leaf/client.

- `sphincs128f-mldsa65-mldsa44-mldsa44` works
- `sphincs128s-mldsa65-mldsa44-mldsa44` works
- `sphincs192f-mldsa65-mldsa44-mldsa44` fails at certgen, error message "Failed to make unsigned root certificate (err -134)"
- `sphincs192s-mldsa65-mldsa44-mldsa44` fails at certgen, error message "Failed to make unsigned root certificate (err -134)"
- `sphincs256f-mldsa65-mldsa44-mldsa44` can generate certificates, but client will complain "Handshake message too large Error (-404)"
- `sphincs256s-mldsa65-mldsa44-mldsa44` works
- tried `sphincs256s-sphincs128f-sphincs128f-sphincs128f`, can generate certificates, but server fails to load private key. Maybe this is the same problem as Falcon? I am too tired to "just continue"

# May 5, 2025

Finish work on porting SPHINCS and Falcon. HQC will have to wait because of [IND-CCA2 security concerns](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/Wiu4ZQo3fP8), which will likely result in some change in the reference implementation.

Finished porting all of `sphincs-shake-XXX-simple/clean` from PQClean to Wolfcrypt. Enable with the `HAVE_SPHINCS` macro. Benchmark results (using `wolfcrypt/benchmark/benchmark.c`) are as follows:

| algorithm         | level | operation | avg time (ms) | avg ops/sec |
| :---------------- | :---- | :-------- | ------------: | ----------: |
| Ed25519           | 1     | sign      |      8.290 ms |     120.623 |
| SPHINCS-FAST-128  | 1     | sign      |    175.822 ms |       5.688 |
| SPHINCS-SMALL-128 | 1     | sign      |   3673.985 ms |       0.272 |
| ML-DSA-44         | 2     | sign      |      0.577 ms |    1732.000 |
| ML-DSA-65         | 3     | sign      |      0.883 ms |    1132.515 |
| SPHINCS-FAST-192  | 3     | sign      |    287.363 ms |       3.480 |
| SPHINCS-SMALL-192 | 3     | sign      |   6491.991 ms |       0.154 |
| ML-DSA-87         | 5     | sign      |      1.149 ms |     869.992 |
| SPHINCS-FAST-256  | 5     | sign      |    597.988 ms |       1.672 |
| SPHINCS-SMALL-256 | 5     | sign      |   5758.303 ms |       0.174 |
| Ed25519           | 1     | verify    |     17.090 ms |      58.513 |
| SPHINCS-FAST-128  | 1     | verify    |     10.469 ms |      95.517 |
| SPHINCS-SMALL-128 | 1     | verify    |      3.285 ms |     304.368 |
| ML-DSA-44         | 2     | verify    |      0.178 ms |    5605.900 |
| ML-DSA-65         | 3     | verify    |      0.290 ms |    3449.601 |
| SPHINCS-FAST-192  | 3     | verify    |     14.887 ms |      67.174 |
| SPHINCS-SMALL-192 | 3     | verify    |      6.223 ms |     160.704 |
| ML-DSA-87         | 5     | verify    |      0.476 ms |    2101.723 |
| SPHINCS-FAST-256  | 5     | verify    |     15.912 ms |      62.846 |
| SPHINCS-SMALL-256 | 5     | verify    |      8.176 ms |     122.306 |

Falcon remains the only NIST DSA that needs to be ported, although porting it will not be straightforward copy/paste because the PQClean implementation does not expose API for passing in its own seed. Maybe I can raise a PR with `PQClean`, as well.

# May 4, 2025

Goal: `sphincs-shake-128f-simple` self-signed certificates.

First need to implement the three basic functions: generate key pair, sign a message, and verify a standalone signature.

What about the OID of SPHINCS keys and signatures? They are probably needed in:

- wc_Sphincs_PrivateKeyDecode
- wc_Sphincs_PublicKeyDecode
- wc_Sphincs_KeyToDer
- wc_Sphincs_PrivateKeyToDer
- wc_Sphincs_PublicKeyToDer

PrivateKeyDecode calls `DecodeAsymKey` from `wolfcrypt/asn.h`. `DecodeAsymKey` calls `DecodeAsymKey_Assign`. `DecodeAsymKey_Assign` will call `OidFromId` if caller supplied key type, which is true in `wc_Sphincs_PrivateKeyDecode`. Check `asn.c` for `keySphincsFast_Leve1Oid`:

```c
// wolfssl/wolfcrypt/src/asn.c
#ifdef HAVE_SPHINCS
    /* Sphincs Fast Level 1: 1 3 9999 6 7 4 */
    static const byte keySphincsFast_Level1Oid[] =
        {43, 206, 15, 6, 7, 4};

    /* Sphincs Fast Level 3: 1 3 9999 6 8 3 */
    static const byte keySphincsFast_Level3Oid[] =
        {43, 206, 15, 6, 8, 3};

    /* Sphincs Fast Level 5: 1 3 9999 6 9 3 */
    static const byte keySphincsFast_Level5Oid[] =
        {43, 206, 15, 6, 9, 3};

    /* Sphincs Small Level 1: 1 3 9999 6 7 10 */
    static const byte keySphincsSmall_Level1Oid[] =
        {43, 206, 15, 6, 7, 10};

    /* Sphincs Small Level 3: 1 3 9999 6 8 7 */
    static const byte keySphincsSmall_Level3Oid[] =
        {43, 206, 15, 6, 8, 7};

    /* Sphincs Small Level 5: 1 3 9999 6 9 7 */
    static const byte keySphincsSmall_Level5Oid[] =
        {43, 206, 15, 6, 9, 7};
#endif /* HAVE_SPHINCS */
#ifdef HAVE_SPHINCS
    /* Sphincs Fast Level 1: 1 3 9999 6 7 4 */
    static const byte sigSphincsFast_Level1Oid[] =
        {43, 206, 15, 6, 7, 4};

    /* Sphincs Fast Level 3: 1 3 9999 6 8 3 */
    static const byte sigSphincsFast_Level3Oid[] =
        {43, 206, 15, 6, 8, 3};

    /* Sphincs Fast Level 5: 1 3 9999 6 9 3 */
    static const byte sigSphincsFast_Level5Oid[] =
        {43, 206, 15, 6, 9, 3};

    /* Sphincs Small Level 1: 1 3 9999 6 7 10 */
    static const byte sigSphincsSmall_Level1Oid[] =
        {43, 206, 15, 6, 7, 10};

    /* Sphincs Small Level 3: 1 3 9999 6 8 7 */
    static const byte sigSphincsSmall_Level3Oid[] =
        {43, 206, 15, 6, 8, 7};

    /* Sphincs Small Level 5: 1 3 9999 6 9 7 */
    static const byte sigSphincsSmall_Level5Oid[] =
        {43, 206, 15, 6, 9, 7};
#endif /* HAVE_SPHINCS */
```

There are different types of OIDs, see `wolfssl/wolfcrypt/asn.h`:

```c
// wolfssl/wolfssl/wolfcrypt/asn.h
enum Oid_Types {
    oidHashType         = 0,
    oidSigType          = 1,
    oidKeyType          = 2,
    oidCurveType        = 3,
    oidBlkType          = 4,
    oidOcspType         = 5,
    oidCertExtType      = 6,
    oidCertAuthInfoType = 7,
    oidCertPolicyType   = 8,
    oidCertAltNameType  = 9,
    oidCertKeyUseType   = 10,
    oidKdfType          = 11,
    oidKeyWrapType      = 12,
    oidCmsKeyAgreeType  = 13,
    oidPBEType          = 14,
    oidHmacType         = 15,
    oidCompressType     = 16,
    oidCertNameType     = 17,
    oidTlsExtType       = 18,
    oidCrlExtType       = 19,
    oidCsrAttrType      = 20,
#ifdef WOLFSSL_SUBJ_DIR_ATTR
    oidSubjDirAttrType  = 21,
#endif
    oidIgnoreType
};
```

I am okay with not updating these OID's for now as long as my handshake works.

Modified `server-wolfssl/certgen.c`: root key is now a `sphincs-shake-129f-simple` key. Need to incorporate the rest of the SPHINCS variations, Falcon, then parameterize the `certgen.c` script

# May 2, 2025

THe OID of [FIPS 205: SLH-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) is being discussed [here](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-x509-slhdsa-06)

<strike>Maybe it is a good idea to simply dump all of PQClean into wolfssl source code since every implementation should be properly namespaced (e.g. `PQClean/crypto_sign/sphincs-sha2-128f-simple/clean` is namespaced with `#define SPX_NAMESPACE(s) PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_##s`).</strike> On a second thought this is not a great idea because I actually need to modify the PQClean source code to use WolfSSL's RNG and SHA2/SHAKE implementations.

WolfSSL needs the (almost) black box implementation of `keygen`, `sign`, `verify`; PQClean needs WolfSSL's RNG and SHA2/Shake.

Resolved a nasty problem where previous installation of WolfSSL (in `/usr/local/include` and `/usr/local/bin`) resulted in conflicting header files.

**How to port PQClean into WolfSSL**:

- definitely need to change source code, so I cannot just do a sub-module
- need to separate headers (`wolfssl/wolfcrypt/pqclean/...`) from sources (`wolfcrypt/src/pqclean/...`), **but how can I preserve the namespacing?**
  - Move all `.h` files from PQClean
  - Move all source files
  - See if things compile

Moving header files to preserve the original PQClean project layout.

Implemented `wc_sphincs_make_key` and `wc_sphincs_make_key_from_seed` using APIs from PQClean's `api.h` headers, but cannot compile because missing source files.

Copy `pqclean/crypto_sign/sphincs-shake-128f-simple/clean/*.c` to `wolfssl/wolfcrypt/src/pqclean/crypto_sign/sphincs-shake-128f-simple/clean/`. There are things I need to change:

- pathing of PQClean header files
- `randombytes.h` needs to be replaced with wolfcrypt's RNG, which means some `api.h` needs to change
- `fips202.h` actually should not be replaced since I am not sure if PQClean's shake is identical to that of wolfssl :(

# May 1, 2025

I want to add implementations of SPHINCS+ and Falcon to WolfSSL without using liboqs.

There are two workspaces to manage:

- `wolfssl`'s source code, located as a submodule under this project. I will not run `configure` within this source code. Instead, I will rely on `wolfssl/.clangd` to set macro flags when working on wolfssl source code.
- `server-wolfssl`, which will compile `wolfssl` using `server-wolfssl/config/user_settings.h` and its cmake setup. This is the primary place where I will be running tests the stuff
- `pico`, this is the final place where the wolfssl changes will go into
