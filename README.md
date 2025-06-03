**what's next**:
- [ ] Write-up
- [ ] Clean-up:
    - [ ] How to add a new KEM and use it for ephemeral key exchange
    - [ ] How to add a new Signature and use it for generating certificates, private keys, and TLS signatures
    - [ ] KEMTLS: load KEM private keys, send/process KemCiphertext, updated key schedule, handling Finished in a different order than in TLS 1.3
- [ ] Decide on which cryptography libraries to use and commit to it. It is probably going to be [PQClean](https://github.com/PQClean/PQClean/).
- [ ] Mutually authenticated KEMTLS
- [ ] Pico as a TLS/KEMTLS server

# Post-quantum TLS 1.3 on embedded device
Content of this repository:
- **pico**: C project for running TLS client on Raspberry Pi Pico 2 W
- **server-wolfssl**: TLS client, server, and certificate generator on desktop environment
- **wolfssl**: a fork of WolfSSL that contains the modifications
- **certificates**: ready-made certificate chains

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
