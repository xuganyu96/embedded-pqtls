# OQS-PKI: Post-Quantum Public-Key Infrastructure
- TODO: the `oqs` wrapper needs some more elegant and locally contained installer


## Getting started
`oqspki` depends on the [Python wrapper of `liboqs`](https://github.com/open-quantum-safe/liboqs-python). As of [1a29e93](https://github.com/open-quantum-safe/liboqs-python/tree/1a29e9342182c829f4fc2ff47b5366796c7ffb64), there is no PyPI entry, so it has to be installed from source:

```bash
# create virtual environment
python -m venv .venv
source .venv/bin/activate

# install oqs from source
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
cd ..

# run examples and check if the library works
python liboqs-python/examples/kem.py
python liboqs-python/examples/sig.py
```

The rest of the dependencies can be installed from PyPI:

```bash
pip install -r requirements.txt
```
