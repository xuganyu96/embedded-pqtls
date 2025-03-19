# Patch files
Minimal efforts for patching the broken build process of [thomwiggers/kemtls-experiment](https://github.com/thomwiggers/kemtls-experiment/tree/62c9d06)

- Update base image of `./Dockerfile` from `rust:1.66-bullseye` to `rust:1.85-bullseye`
- Added `--cap-lints warn` to all rustls builds
- Put `encoder.py` setrlimit calls within a try-catch block and only warn if limits cannot be set
- Removed `#![forbid(...)]` and `#![deny(...)]` in `rustls/rustls/src/lib.rs`
