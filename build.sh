#!/bin/bash
#
# Wrapper script around https://github.com/thomwiggers/kemtls-experiment/

setup_experiment() {
    local kex="$1"
    local leaf="$2"
    local int="$3"
    local root="$4"
    local client_leaf="$5"
    local client_ca="$6"
    local keygen_cache="$7"

    echo "Setting up experiment with the following parameters:"
    echo "KEX: $kex"
    echo "Leaf: $leaf"
    echo "Intermediate: $int"
    echo "Root: $root"
    echo "Client Leaf: $client_leaf"
    echo "Client CA: $client_ca"
    echo "Keygen Cache: $keygen_cache"

    # Check if patch-files directory exists
    if [[ ! -d "patch-files" ]]; then
        echo "Error: patch-files not found, are you at project root?"
        exit 1
    fi

    # Download source code and patch the files
    if [[ ! -d /tmp ]]; then
        echo "Error: /tmp does not exist! Creating it..."
        mkdir -m 1777 /tmp || { echo "Failed to create /tmp"; exit 1; }
    fi
    builddir="/tmp/kemtls-experiment"
    git clone --recurse-submodules https://github.com/thomwiggers/kemtls-experiment.git $builddir
    cp patch-files/Dockerfile $builddir/Dockerfile
    cp patch-files/encoder.py $builddir/mk-cert/encoder.py
    cp patch-files/rustls-lib.rs $builddir/rustls/rustls/src/lib.rs

    # Run the experimental setup script with provided parameters
    $builddir/measuring/scripts/create-experimental-setup.sh \
        "$kex" "$leaf" "$int" "$root" "$client_leaf" "$client_ca" "$keygen_cache"
    # TODO: maybe also make a two scripts "start-server.sh" and "start-client.sh"

    # Copy over build artifacts
    mkdir -p ./target
    echo "Copying build artifacts into $(pwd)/target/"
    cp -r $builddir/measuring/bin/* ./target/

    # Clean-up
    rm -rf $builddir
}

# example: 
#     setup_experiment "Kyber512" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2" "Y"

# TODO: include SPHINCS+
# TODO: include one-time KEMs
# >>>>> PQ-TLS setups, including server and mutual authentication
setup_experiment "Kyber512" "Dilithium2" "Dilithium2" "Dilithium2"
setup_experiment "Kyber512" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2"
# setup_experiment "Kyber512" "Falcon512" "Falcon512" "Falcon512"
# setup_experiment "Kyber512" "Falcon512" "Falcon512" "Falcon512" "Falcon512" "Falcon512"
# setup_experiment "Hqc128" "Dilithium2" "Dilithium2" "Dilithium2"
# setup_experiment "Hqc128" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2" "Dilithium2"
# setup_experiment "Hqc128" "Falcon512" "Falcon512" "Falcon512"
# setup_experiment "Hqc128" "Falcon512" "Falcon512" "Falcon512" "Falcon512" "Falcon512"

# >>>>> KEMTLS setups, including server and mutual authentication
setup_experiment "Kyber512" "Kyber512" "Dilithium2" "Dilithium2"
setup_experiment "Kyber512" "Kyber512" "Dilithium2" "Dilithium2" "Kyber512" "Dilithium2"
# setup_experiment "Kyber512" "Kyber512" "Falcon512" "Falcon512"
# setup_experiment "Kyber512" "Kyber512" "Falcon512" "Falcon512" "Kyber512" "Falcon512"
# setup_experiment "Hqc128" "Hqc128" "Dilithium2" "Dilithium2"
# setup_experiment "Hqc128" "Hqc128" "Dilithium2" "Dilithium2" "Hqc128" "Dilithium2"
# setup_experiment "Hqc128" "Hqc128" "Falcon512" "Falcon512"
# setup_experiment "Hqc128" "Hqc128" "Falcon512" "Falcon512" "Hqc128" "Falcon512"

# >>>>> KEMTLS-PDK setups
setup_experiment "Kyber512" "Kyber512" "" "" "" "" "true"
setup_experiment "Kyber512" "Kyber512" "" "" "Kyber512" "Dilithium2" "true"
# setup_experiment "Kyber512" "ClassicMceliece348864" "" "" "" "" "true"
