# WolfSSL dev log

**Table of content**
- [Introduction](#introduction)
- [Project setup](#project-setup-and-development-environment)
    - [Neovim](#neovimlsp-setup)
    - [VSCode](#vscode-setup)

# Introduction
For my Master's thesis, I wanted to implement post-quantum TLS 1.3 and apply two performance optimizations aimed at reducing the handshake latency (we will discuss what "reducing handshake latency" in details at later section).
While integrating post-quantum cryptography (PQC) and implementing implicit authentication (more on that later) have both been done before, but executing it all on WolfSSL proved to be a genuinely challenging project.
In the process, I've learned a great deal from the mature, production-grade source code of [WolfSSL](https://github.com/wolfssl/wolfssl).
I now wish to document and share my journey into a serious TLS/SSL/Crypto stack.

# Project setup and development environment 
This project will have several moving parts:
1. The WolfSSL source code
1. Some provider of PQC implementations.
in my thesis work I chose to work with [PQClean](https://github.com/PQClean/PQClean/), but there are other options like [liboqs](https://github.com/open-quantum-safe/liboqs) and [pqm4](https://github.com/mupq/pqm4).
1. Some desktop programs: certificates, server, client, etc. Preferably they are portable, so I can compile them on my laptop (Apple Silicon) and/or on a linux desktop (`x86_64`).
1. Some embedded programs, specifically a client.

This would translate the following project structure:

```
root/
    wolfssl (submodule)/
    pqclean (submodule)/
    server/
        src/
        include/
        config/
        CMakeLists.txt
    pico/
        src/
        include/
        config/
        CMakeLists.txt
```

We will begin by setting up the sub-modules.
Since we will make modification to both WolfSSL and PQClean, it's probably a good idea to fork the repositories.

```bash
git submodule add git@github.com:xuganyu96/PQClean.git
git submodule add git@github.com:xuganyu96/wolfssl.git
git submodule update --init --recursive
```

The submodules will each track the fork.
Use `git remote` to add the original repository so we can pull commits and stay up to date.

```bash
# from project root
cd wolfssl  # or pqclean, we will omit duplicate commands for pqclean
git remote add wolfssl git@github.com:wolfSSL/wolfssl.git
# to incorporate remote commits, I prefer pulling into a local branch then rebase,
# but using `git pull --rebase`
git pull wolfssl master
```

Last but not least, with each submodule, we want to be working on a separate branch from the main branch.

```bash
# from project root
cd wolfssl
git checkout -b feature/pqclean-integration
git push -u origin feature/pqclean-integration
```

## Neovim/LSP setup
> **TRIGGER WARNING**: the author is a die-hard Neovim cultist.
[Skip this section](#vscode-setup) if you are allergic to Vim elitism.

My current development setup uses Neovim, within which I use [Mason](https://github.com/williamboman/mason.nvim) to install and manage LSPs.
For C programming, I use `clangd`, which requires a bit more configuring before the LSP can properly navigate WolfSSL's source code.

```yaml
# save this .clangd at wolfssl source code root
CompileFlags:
    Add: [
        "-DWOLFSSL_USER_SETTINGS",
        "-I/Users/ganyuxu/opensource/embedded-pqtls/wolfssl",
        "-I/Users/ganyuxu/opensource/embedded-pqtls/server/config",
        # "-I/Users/ganyuxu/opensource/embedded-pqtls/pico/config",
    ]
    # Compiler: "/opt/homebrew/bin/arm-none-eabi-gcc"

```

What are these?
- `-I/project_root/wolfssl` tells `clangd` that this directory will be among the "include" directories (we will configure that in cmake), this allows the LSP to search for WolfSSL header files such as `wolfssl/wolcrypt/settings.h`
- `-I/project_root/server/config` is a directory that contains the user setting header file `user_settings.h`.
This and `-DWOLFSSL_USER_SETTINGS` together configure LSP to read compile-time configurations from the user setting header instead of the `config.h` file generated from `autoconf`.
I chose to work with `user_settings.h` so I can have different compilation configuration for `server` and `pico` while maintaining one copy of WolfSSL source code.
According to [this GitHub issue](https://github.com/clangd/clangd/issues/642), `.clangd` can also specify `Compiler`, which would be useful since `pico` will be cross-compiled with `gcc-arm-none-eabi`, but hopefully we will not make any non-portable changes to the WolfSSL code base.

Last but not least, one can optionally put a `.clang-format` file at project root, but WolfSSL is a big project and I don't want to pollute `git blame` with style changes.

## VSCode setup
200ms key input lag, seriously?

