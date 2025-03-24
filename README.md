# What's next
- [ ] Fix one set of algorithms (ML-KEM-512 and ML-DSA-44) and implement all algorithm variants
    - [ ] PQ-TLS
    - [ ] KEMTLS
    - [ ] KEMTLS-PDK
    - [ ] PQ-TLS w/ certificate caching (for comparison with KEMTLS-PDK)
- [ ] Implement one-time ML-KEM and one-time HQC
- [ ] Compile other PQC algos and enrich experiment
- Other angles to consider
    - NIST PQC usually mandates using SHA3, but Keccak requires a 1600-bit state and usually does not have hardware acceleration. If the embedded system has a strong source of randomness (hardware random number generator), maybe we can replace SHA3 with hardware-generated random bytes? There are also other choices: AES-CTR, Ascon, etc.
    - Other system architecture? Raspberry Pi Pico 2 also has RISC-V cores. Cortex-M33 is comparable to Cortex-M4, only it has more features (floating point, TrustZone, etc) slightly more frequency and per clock cycle efficiency (I should be able to pull implementation from pqm4 if I need optimized implementations)

## What combinations do I want to implement?
Classic TLS, PQ-TLS, KEMTLS, KEMTLS-PDK
- classic TLS: X25519 for key exchange, RSA2048 for all authentication
- ephemeral key exchange: ML-KEM, [HQC](https://csrc.nist.gov/pubs/ir/8545/final), one-time ML-KEM, one-time HQC
- server/mutual leaf authentication: ML-KEM, ML-DSA, SLH-DSA, FN-DSA (Falcon), Classic McEliece (for PDK only)
- server/mutual int/root authentication: ML-DSA, SLH-DSA, FN-DSA

non-goals for now:
- non-standardized PQC algorithms (CROSS, MAYO, UOV, etc.)
- hybrid (e.g. X25519MLKEM768)

# KEMTLS

## References

```bibtex
@InProceedings{CCS:SchSteWig20,
  author =       "Peter Schwabe and
                  Douglas Stebila and
                  Thom Wiggers",
  title =        "Post-Quantum {TLS} Without Handshake Signatures",
  pages =        "1461--1480",
  editor =       ccs20ed,
  booktitle =    ccs20name,
  address =      ccs20addr,
  month =        ccs20month,
  publisher =    ccspub,
  year =         2020,
  doi =          "10.1145/3372297.3423350",
}

@InProceedings{ESORICS:SchSteWig21,
  author =       "Peter Schwabe and
                  Douglas Stebila and
                  Thom Wiggers",
  title =        "More Efficient Post-quantum {KEMTLS} with Pre-distributed Public Keys",
  pages =        "3--22",
  editor =       esorics21ed,
  booktitle =    esorics21name1,
  volume =       esorics21vol1,
  address =      esorics21addr,
  month =        esorics21month,
  publisher =    esorics21pub,
  series =       mylncs,
  year =         2021,
  doi =          "10.1007/978-3-030-88418-5_1",
}

@Misc{EPRINT:GonWig22,
  author =       "Ruben Gonzalez and
                  Thom Wiggers",
  title =        "{KEMTLS} vs. Post-Quantum {TLS}: Performance On Embedded Systems",
  year =         2022,
  howpublished = "Cryptology ePrint Archive, Report 2022/1712",
  url =          "https://eprint.iacr.org/2022/1712",
}
```
