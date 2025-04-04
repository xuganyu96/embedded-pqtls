- [ ] Benchmark post-quantum primitives on Pico 2 W
    - [x] ML-KEM
    - [x] HQC
    - [x] ML-DSA
    - [x] Falcon (FN-DSA)
    - [ ] SPHINCS+ (SLH-DSA)
    - [ ] one-time ML-KEM (not yet implemented)
    - [ ] one-time HQC (not yet implemented)
- [ ] Get Wifi working on Pico 2 W
- [ ] Get WolfSSL working on Pico 2 W
- [ ] Start modifying WolfSSL for PQ-TLS and KEM-TLS

# KEMTLS and PQ-TLS on Raspberry Pi Pico

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
