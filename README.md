- [ ] Networking stack on Pico
    - [ ] DNS: resolve hostname to IPv4 address. IPv6 is a non-goal for now
    - [ ] NTP: obtain time from network and sync local clock
    - [ ] TCP: can connect and listen
- [ ] Certificate and key management: CLI application for generating certificate chain and keys
- [ ] FIPS compliant TLS 1.3 handshakes
    - [ ] ECDHE + RSA/ECDSA/EdDSA
    - [ ] ML-KEM/HQC + RSA/ECDSA/EdDSA
    - [ ] ML-KEM/HQC + ML-DSA/SLH-DSA/FN-DSA
    - [ ] Mutual authentication, but without secret key protection
- [ ] Further improvements
    - [ ] Protect secret key in client: OTP memory in Pico, generate signing key from seed
    - [ ] Cache leaf certificates (RFC 7924): client sends some id in `ClientHello` so the server does not need to send `Certificate`
    - [ ] KEM-based authentication
- [ ] **DTLS** seems to also be a good fit for secure embedded communication

# KEMTLS and PQ-TLS on Raspberry Pi Pico
Content of this repository:
- **pico**: C project for running TLS client on Raspberry Pi Pico 2 W
- **server-wolfssl**: TLS client, server, and certificate generator on desktop environment
- **server-rustls**: some wrapper scripts around Thom Wiggers' original repository

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
