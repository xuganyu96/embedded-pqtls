# WolfSSL dev log

## May 1, 2025
The initial goals are to port Falcon and SPHINCS to wolfcrypt. According to the [installation instruction](https://github.com/wolfSSL/wolfssl/blob/master/INSTALL), "primary development uses automake", which will generate a `wolfssl/options.h` that may interfere with builds that use `user_settings.h`, so a separate copy of WolfSSL source code is checked out elsewhere for development.

After cloning:

```
./autogen.sh
./configure
make
make check
make test
```

