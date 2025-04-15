# slim is ~800MB where as non-slim is ~1.4GB
FROM rust:1.85-bookworm

# System-wide requirements
RUN apt-get update \
    && apt-get install -y pipenv

# Replicate thomwiggers/kemtls-experiment/measuring/scripts/create-experimental-setup.sh
# Create keys, certificate, and certificate chains
# Build TLS server and clients
# Clean up


