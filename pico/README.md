# Embedded post-quantum TLS on Raspberry Pi Pico 2 W
The source code repository of firmwares to be tested on the Pico 2 W. To build this project, make sure `PICO_SDK_PATH` is set, and `wolfssl` submodule has been updated

```bash
export PICO_SDK_PATH="path/to/pico/sdk"
mkdir build
cmake .. && make
# plug in the pico
picotool load -f firmware.uf2

# readserial.py replaces minicom
pip install -r requirements.txt
./readserial.py /dev/tty.usbmodemXXX [-C logfile]
```

The `readserial.py` script conveniently replaces `minicom`, 

Currently this project builds the following firmwares:
- `test_tcp_stream`: test my TCP stack
- `https_client`: sends a HTTP request to https://api.github.com/octocat and reads the response
- `tls_client`: repeatedly performs handshake with some server and measures time
