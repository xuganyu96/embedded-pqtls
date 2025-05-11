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
