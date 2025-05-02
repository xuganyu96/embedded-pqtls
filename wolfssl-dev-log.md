# May 2, 2025
THe OID of [FIPS 205: SLH-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) is being discussed [here](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-x509-slhdsa-06)

<strike>Maybe it is a good idea to simply dump all of PQClean into wolfssl source code since every implementation should be properly namespaced (e.g. `PQClean/crypto_sign/sphincs-sha2-128f-simple/clean` is namespaced with `#define SPX_NAMESPACE(s) PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_##s`).</strike> On a second thought this is not a great idea because I actually need to modify the PQClean source code to use WolfSSL's RNG and SHA2/SHAKE implementations.

WolfSSL needs the (almost) black box implementation of `keygen`, `sign`, `verify`; PQClean needs WolfSSL's RNG and SHA2/Shake.



# May 1, 2025
I want to add implementations of SPHINCS+ and Falcon to WolfSSL without using liboqs.

There are two workspaces to manage:
- `wolfssl`'s source code, located as a submodule under this project. I will not run `configure` within this source code. Instead, I will rely on `wolfssl/.clangd` to set macro flags when working on wolfssl source code.
- `server-wolfssl`, which will compile `wolfssl` using `server-wolfssl/config/user_settings.h` and its cmake setup. This is the primary place where I will be running tests the stuff
- `pico`, this is the final place where the wolfssl changes will go into