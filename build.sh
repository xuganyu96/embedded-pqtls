#!/bin/bash

# Download source code and patch the files
git clone --recurse-submodules https://github.com/thomwiggers/kemtls-experiment.git /tmp/kemtls-experiment
cp patch-files/Dockerfile /tmp/kemtls-experiment/Dockerfile
cp patch-files/encoder.py /tmp/kemtls-experiment/mk-cert/encoder.py
cp patch-files/rustls-lib.rs /tmp/kemtls-experiment/rustls/rustls/src/lib.rs

kex="Kyber512"
leaf="Kyber512"
int="Dilithium2"
root="Dilithium2"
/tmp/kemtls-experiment/measuring/scripts/create-experimental-setup.sh $kex $leaf $int $root

# copy over build artifacts
cp -r /tmp/kemtls-experiment/measuring/bin ./target

# clean-up
rm -rf /tmp/kemtls-experiment
