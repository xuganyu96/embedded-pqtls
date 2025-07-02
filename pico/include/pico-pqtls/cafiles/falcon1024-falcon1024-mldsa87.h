#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "falcon1024-falcon1024-mldsa87"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIINVjCCCEmgAwIBAgIQYHUUtkgD3Amm+FvBHViwEjAJBgUrzg8DCQUAMG8xCzAJ"         \
    "BgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAhBgNV"         \
    "BAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVuZy51"         \
    "d2F0ZXJsb28uY2EwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMIIHDzAHBgUrzg8DCQOCBwIACn+FCIGh0DJixZHiOGv8II7L"         \
    "pspjoqjygIrapk6X/NjygJQ1nzh/0eIcRRRaV9D7Cah6kkwTRRjrBB7oSgXt+Gzh"         \
    "OolintGkVYrhIANsu1YOJdKj4ik6rstRFDFxjYN0CZHAvfWfhM1nTHlB6oDaovx4"         \
    "ZnuCVpvirmoSFrAlowMhEaFsBJA7el8nks8yTQpBJ/YSSL89HavtKm0qoN3WLWik"         \
    "cyZw5zjXkwTiqqo9YgFBvn3FWOiuviLyJtfPx5IREjG4mhZxnZYaodOBiSRjmHdd"         \
    "FoeMdalSZGSZcgSnR1Yvla7HyUun4Bv48ccLQm2ZkqI0V16+hjSV0JzUOR/CcljS"         \
    "zXwZyAtUMZJnOnSIOIqHgWG+0Ri/J0KdzdCl59NaTOyJIEupj5omHEt/lpEnVUbC"         \
    "zIFHJm55K6IfJg0IlZYJoBwvrFwgM4QdCAJPK7coArp0uuq/oJWE2WXYJsu9HUVh"         \
    "RmFkPqn6D+PSYIIFkMdKe9lGokTRuZORJKkOxykRE/cstpq7JOQPp6G+MQ7dqLod"         \
    "Y+fKZHMXBsaoPIkNrfF6sonoM6dYnABQaVGkKDE4qgY/FLVgGZWcpruY56fB4QhA"         \
    "kDG446PIbEUehZiY7l0B6cHoL5grcv43T2PpAEFPqfLt3rl06vLziek9PnBGoSFO"         \
    "fopDGM9dAEXNe7Xf15Nbzp1YpVCSc7wgwO9QJhS5wRQSTyhbWZnZTh43Aoi5CeJr"         \
    "S09dtZNjyZR4WvERUc/8lMAeFTWep3/MdYc146qd8ucJrdg4nIw0Ry5N4VZ+6CHh"         \
    "HjmoKdz0Ut0PT5gtIgqKPlyQFCHmLOpQEUyBxARztnGEtIuNHyMuNVtFR/UWve/2"         \
    "jGojoBTlBP7EJ53xMvZZbiZ7Uq2xk+IPWUGHEFFMbHGgzrQ1ZkNgxlY214YzMMpf"         \
    "yTCYu2mO5YsHq6u4OVGR/Io5gv5+MWOFSIq87UL5KHuFYpmUD+5POpAQ+1nIo524"         \
    "SRWJJ8ESBm7qI29OhuyQqPSGVbyZAgQh1XSctbyIxs+AoG0NASZAC38W/HqGIZsl"         \
    "jisqSIA9hGH8h+4Guh3lQ/gBiu8xlrqA+1IAr+kGFJ0dC0q2X1PbnOwvDKdwCYnx"         \
    "I1BeKF1lOSExF8R5T0hhrGQi/0wVMnSoKjdbCxmtQ4fsynKEqDWVeAkRZB6LsxUG"         \
    "mIsOHmp4yLCwwTviCwoYUVAHG0Qm4gvgboMU3PRVYTzJRO0alupjmwKvqnYeZmJ6"         \
    "xtGLmlShLZ/HGjr6Qf7UYbiW3yHFXRy9dDf4rF4uppL+8Qrm31kqzWpnXRk5Mse3"         \
    "JVXJZ7aJuy0UZiNNC+hWkeiRYecgNxqMILQw+7sYDV6E8qeUJCG4Ie1wFRJGS31M"         \
    "25iA4xFOdpAxndRGrNGHDcDlsT5m0a7MJ7LwckPV3xO1FdIZs9Ubjs1Q5IITUzAV"         \
    "zHW+YfIJxDf6pR7XLpF6acoixAhUARSDY3S0evL7whYTviRokZIfOZxtqxd/3kew"         \
    "1V7AJsMtOkhliGsoDyeCUdkGWCoEQOaEvhVyRwJq1VucERyp55YeBuKaWI0J+ElN"         \
    "UCrmGDvH/BbUbQpeIgcPcmygelauOtCCFRil76Z6l3ctVhy2PLu4/pmJVvw2SgtW"         \
    "QVpk2cGDHthWIrDBbE4uIh1gp4DphZMkRdFwHY0s+KJmRM64PeCm8PEVRFjq1fgL"         \
    "RQk2sDiRlW0LkPaEUP+dYw4kpssMoTBW4sJFnmp5ruav8mVoGL6wfTcm4pajadIk"         \
    "V6NHQe1Eo6aRIy+RU7dEQ8aVmUtzU+fEmgWdp12QFR4Zb7OBk21qMlyU4iaTk4Vy"         \
    "9QdYEqP9QyGNLfAUzRW56JXiLHZRYgac5F7W+yRPSlFfoaRi3deGV9F6lq9rR4rm"         \
    "e1LSn1endv9HFQsJpyxLAEoecGi0CppXy21MRR5WX+pwSLDI4wphOL/c2jEVT89p"         \
    "KD3A9qZVjPLKUeTZgFr+LuFoARCSsiT3xSGSpUr0y37YpAgadeNBFY8I2Xn28J2q"         \
    "f4Fd5MCAErCk0WGZHORshCBJY0KqabQGA77QtJ2A9IeeWWUUdomYMtSWiNGPAH1B"         \
    "FJGpnZAbTr9xRAVr+2lnGkhaGspU3p/CC5ncRaCjreRXBJ/4LPJ/GlEI60JiDECL"         \
    "6W0p4mSEuCc7IOwjYgbM81wJJUpkUCtN3aKCoe2MIEW/RrrvxB7gmCphgJKVcdCk"         \
    "ncJRsPFFFPuUu2VqBxTUnCctSQPS64jPIOAmUaZEZ1E6ueCdLj5/pRPiVh1wDUUv"         \
    "BC2sxjIcMkdChhVSKF+FfkXrgxGl+n5Unr9k00p6mTsxcHdybyCBBZ6BQ1HSCo8s"         \
    "8GfcgM42oFTb8dH5UlYnWiYEggamf9i8ICEZwhexTtUsZxHxBZQalrOQnkPM19Cj"         \
    "EDAOMAwGA1UdEwQFMAMBAf8wCQYFK84PAwkFAAOCBPoAOjnhCRNFgNd4JB7yn0/E"         \
    "quM+ranARfpdnJO7/cvJ1kO/IfrL3MgsEDEDkE027Zl4S9JyhulS6sxOs7ffjJEe"         \
    "ik0m8eMYR7oQ3sfFkdvw37BVpuqo8KCFm2haOfjkGkYxrISRAzXIyxfozyLQl0WH"         \
    "GLQI7PzKWkKGpZ6VWoq2KjuKdo5IiUq1EdJa2nZlBhiGGbx68qhvt//MaW+8MDEm"         \
    "YSvQJZtbD/fbOa3LXpjrD7ZYMocrJc3P6Tuc6hrjm3c0aeYTheOe+QwDVHdaTXMg"         \
    "wzDGTs+JRJSGaIGq65Qy8o051oOi6SJWl+VH4LB7hI0HQ9y+KR+6PfBBLIizkGSh"         \
    "SGdKkZalcPUJYKOhzMJOfWlrczUmhGwRCty64U6ROrnBPcZzqCdy7saxXS20TbLc"         \
    "qfUkeu0i5+wyFTo0ww/mTnNjFQknSVKQkMiaVwfVgXkzRmt7mdY5GLdCrmeMUKtL"         \
    "eUx6Tznly0pa4MJqsHBmkbLiLaSFiG5oQ+jm2nTvdh8+83KSNn0butrNkkz140X+"         \
    "cwvlN7c8goVWZu2MEu+wzeYdQk7K5dQ7w1u2cbfWdgbdZ8hpkuRyWtStTwuPzI5D"         \
    "S7wzHRA67jw7h5/BfZoxiKcmiN+pZ/HrCg/W9PG7R3cKWqMQvAILEIWm8ly01oES"         \
    "f9CmtlI2j6SSv7mpQFGeneOdoe1jSEtFPNE8W3suG2Zc12ZhWdOzKtx5LzIZxGG4"         \
    "dCRdh28lzmg5Iq8Ftdza61W3k1aY8rdZ7ArryJIZ8kL0lfFnXtI8MwTqj5PWZrJa"         \
    "P3RJCELgKF8vjxOcoycNBENUlJawqnHpE+uo4XM0zbaOcM191gd+1JhApAZkTdHE"         \
    "D+SiP6y24R3U8jlVRQ4+gDNp13ZUnEwguc3hK5msyYOGX1q3ZjDB+G08frDQQw9j"         \
    "Ll8La2eSXxg/X7/PbHh3GwnOqY2Fauk5ipxc5aCeHM5KpRxlfb/f82vjZVI4ty67"         \
    "Y/lx25SRW/VEM6nJT9MtMMcRA84QBXodgqQjhqIAiRm+1FKkk2OxBF/7kllzLUyM"         \
    "9tEVBd1jPnR5HhO2gVXQUhROCwKmbdhI+6yTzUx2NNGSrXaT5R1M8xWGQtq0bSgx"         \
    "tA0ndQ0S27BCk/haRRZw4XBGtjMVGSXbV1Z3sUUcmeSI06tzgLCRm85csZDns6iJ"         \
    "qV2Hhb3uHfXl43JhiTV44qGKoMzh2gVW1ZR3Zc0PRnXHMxJGMaOzaxOy5O9QNc5y"         \
    "auPECoPIvMdQVVWBZt6JPpbX59y5jTtjl4XK4S9ONcfTM7IDHF+bPqwMr6sSI+vw"         \
    "1lPP4rCt9b8oQ8sejr6nf4VobreYlFIOhaB4Bil/imHj39dqWcndTNSL6ueNmdHj"         \
    "SDEWs+x9iFEGd5mWof3l+I3drj8YXlFhp8Cys/VLvO+4D2/LB+Zgheb34nW3T0J+"         \
    "gtBIz2oJkN7B6+u+zxVFIVWYhPcagGJSURqdI4xuzx+GyXD67D4yWQgyC7M+h+dP"         \
    "K30kbCuPfj2Lyj0XhZZjCzZ2K90BIDuZjMylrDnV29+rp6JVdh8Ya2rGKzEepX3Z"         \
    "TylTFjnGvcORmSO9NX91XjjrA8sp2HgwwRAGQYI2iew1POsevhKXMTHwcsNIhOTa"         \
    "3AwJVtK6Glcyrx/znRa6ltOny+7TSS36SH6yauMdhiQ+XQvN01IyPEfXx1TDl3n1"         \
    "RwLapQTLqRa9oA=="                                                         \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif
