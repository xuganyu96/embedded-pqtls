# May 8, 2025
- Cannot use Falcon/SPHINCS as leaf or client key
- Implement OT-ML-KEM

Thom Wiggers [SPHINCS+ or Falcon for leaf certificate](https://github.com/thomwiggers/kemtls-experiment/blob/thesis/measuring/scripts/experiment.py)?

## Implement OT-ML-KEM
Should I start with PQClean or WolfSSL? I will try porting PQClean's ML-KEM into WolfSSL and compare performance. If performance is comparable then I will modify PQClean's implementation into OT-ML-KEM.

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

|algorithm|level|operation|avg time (ms)|avg ops/sec|
|:---|:---|:---|---:|---:|
|Ed25519|1|sign|8.290 ms|120.623|
|SPHINCS-FAST-128|1|sign|175.822 ms|5.688|
|SPHINCS-SMALL-128|1|sign|3673.985 ms|0.272|
|ML-DSA-44|2|sign|0.577 ms|1732.000|
|ML-DSA-65|3|sign|0.883 ms|1132.515|
|SPHINCS-FAST-192|3|sign|287.363 ms|3.480|
|SPHINCS-SMALL-192|3|sign|6491.991 ms|0.154|
|ML-DSA-87|5|sign|1.149 ms|869.992|
|SPHINCS-FAST-256|5|sign|597.988 ms|1.672|
|SPHINCS-SMALL-256|5|sign|5758.303 ms|0.174|
|Ed25519|1|verify|17.090 ms|58.513|
|SPHINCS-FAST-128|1|verify|10.469 ms|95.517|
|SPHINCS-SMALL-128|1|verify|3.285 ms|304.368|
|ML-DSA-44|2|verify|0.178 ms|5605.900|
|ML-DSA-65|3|verify|0.290 ms|3449.601|
|SPHINCS-FAST-192|3|verify|14.887 ms|67.174|
|SPHINCS-SMALL-192|3|verify|6.223 ms|160.704|
|ML-DSA-87|5|verify|0.476 ms|2101.723|
|SPHINCS-FAST-256|5|verify|15.912 ms|62.846|
|SPHINCS-SMALL-256|5|verify|8.176 ms|122.306|

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
