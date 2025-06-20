#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "sphincs128s-sphincs128s-sphincs128s"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIgJzCCAWSgAwIBAgIQW9MqjU7WHuvvn/WL8vE8YjAIBgYrzg8GBwowbzELMAkG"         \
    "A1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEGA1UE"         \
    "CgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5nLnV3"         \
    "YXRlcmxvby5jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMG8xCzAJ"         \
    "BgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAhBgNV"         \
    "BAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVuZy51"         \
    "d2F0ZXJsb28uY2EwLTAIBgYrzg8GBwoDIQDygyAr8HT12d+Z15WqaZmy+OcHyJgN"         \
    "X57BcOJMWIG2xqMQMA4wDAYDVR0TBAUwAwEB/zAIBgYrzg8GBwoDgh6xAEe5QiF3"         \
    "jcH7NP4FX7vcE/UaNg0HZdYkDb1DZC+rAW7qVDC5vT+Vn5eZ7JMhT8+WcHu2D/Z7"         \
    "TjsUKvD0Ks+thcYEGkINt9O1CO0Zt1PQCz5xKkj+7S/3p4b/BKIjTcC/XvVrMoG5"         \
    "lSQS6Azg6UwSgScc75yItRu3kg2Fsu3f+hKKr5cvebOoiuv5D0Q5medE6CJIIBJm"         \
    "5WUFLO4tRivASPfxEhyKKkrLkXbbgQKTm67fAj9mk1hW4vntLZ8bWKaC+pkt0A7W"         \
    "JhWEhMoRbrqZkV0BQfZObDZPdnDVGMdAuaYbQ7K2vXeVovj5iqHYpMDMvhohlYjB"         \
    "51QCo/v37238XQb2qFxWHCpp5vXAKixy2x1Mc1xoa9AtHGVEOXtx+OYuBrufUron"         \
    "7zBvOvo1CQ6OH7VWYbI5ga5WF/zs5l7SF8nn2IHDcq2gSG+FfhKyT2ZI4l3quMz0"         \
    "N6p3tKsg4O3sNVB6KEiytlNZBUTGDJ8c27mzaxj/AHD9FYmM+h7nTRYlrRV4w1si"         \
    "OCfngBI/3SsF56iG8xUbfqOhWeq3Quu0CeRbec0BIAhMnku72iHp6vwICcuo11tJ"         \
    "F4bUuj1TwkzXvyc6p4xNrhwrne5mLj40Ke8Vnj6x8eyTv2oolARSjCDCAAhkO5vS"         \
    "5xLOhhqCRQ/C47zS+3Vh0p0z/2JRucHETNV47uYwKm9IGS4ktuNMN4w3aRrKKXUx"         \
    "YBb/MDUP2YqW8lOnjGRZXT5XT4AY9lf5luK580WkaPDMuhxP5x9KZpoSRQy4VsnG"         \
    "rilrla/zrBHZv829lhuyVQ17ZaVAhjE3CH9Hl6zsieMpANg0ZneCAxveFWssoor+"         \
    "vXESFTf/xQvLMbbY3j/9DN2jkiAh8ZhGjGZf7PaiFxyHuOwFxpK863vtvWXhaOu/"         \
    "fPG9RIXY+WkIt5I4/OHFqT3DyUSQ7xGsBKJsUiuT2K/Erafyv4yjgGqeJYYv7Jq0"         \
    "WE+tZyePxvwIOmV3d2hIWjr5QgnH++k1Bespu54BtbmBFX6r4S7WvnpMjiHSrofa"         \
    "yriYB3mnXihDOGKDqJq1YJpcCAxtZQ90eLWIRryZX5GzYMyni/CgvdNr0UsMhELg"         \
    "HAZIfDXMk6GSu8eptORMxunrWcPakB/CklFKYoDV53+NAIwtuTukHoIab1vodiJG"         \
    "fJUsjsH4st0KTHN3hEm2MjIGUZKkZ0pTiUYCrxKRb8xPDOg2u+egwK56QP0mxCfS"         \
    "D9PSWF2ho+HzjIG8pOGxHEtdTVrTFG5aqEa3Cny7/Fkpasqe5ebCeA2BQZtbqGJI"         \
    "H67WNMn97dvje5j29TcDQVXNS3IkNqbQIrAxxG1tmFL4GKoXPV81OALs/caOhG4e"         \
    "LDBmAK3cOhJKMAjQo0D1pVNxRKkUztLRqj2X8ct6AxkElxXJ5WcOjg3uNqnlaEV4"         \
    "9/vDMM50tLg0Ccz0nogp3lpVkd2HLC7qrbHzF8+VSCVL1gh5MUS0ze96+NxgHBPD"         \
    "/oYPSn6/IeT9EwbmMYmEWtnNm6wk2JMb2ZiVaDjQ8w2Ykjui/5q1fh5781DLiokH"         \
    "gOvuGHYMXD1E0aiNbUEjj1d62tJNKgHRCqZGX0uQYkuD+2dc06YGS8jXz1bTDg5z"         \
    "iRevrg4XO9ygzQ3p/XglGqWrtRpyxu5zj6WyEXU751tjeoubNWDqCqd0OIQTUlFU"         \
    "Swhk/VbHnLImYYedxJ0L0OW9AakSD7nwhRD8Uy3+oXOl2QjpQDvSKlBoY4BeU0r4"         \
    "AI8fUt4Y6Qlfk65atHvi1rHassdSt+Y9hXr4Rh4Am+7dhmMySmJmRjHShln8xKnX"         \
    "Wgvn5O/Zj6tNU7K9KvgZ4z+AeMzhkmenhNVvQBpSGahIrwMioMiDrkG8yxNoKVl8"         \
    "d4I6kbHy74jof5YBivbFVhf5nUgoy4LpxN08OoLEJdxJOc9g9Az/nK+W/TNqLvl/"         \
    "9CHEq4b1Q7iMm7xC6CXEPb6bd+jpSc3S8/q7lzr9/R2rT3mTlcjLLASUHebiU+7D"         \
    "ZDndH7wxY8IAlPjiLQ7rdCrpaR3Ea4xbF8SmrJOj+ZHaBX7F/OkmaRzMEF+7c1XG"         \
    "ruCF5zaKnuvxrtSxa6jihnhsKP10q+24VilVfP5pYyjSDVKjvIyX3itd3Z4OHWvS"         \
    "pyabdb/QPFIctloMpVlawXoHTTHO2BSj+gJxJOR1Y/4iwABJbVKdg5SSw5C0OxSb"         \
    "pn14C9BPfKGXKN/32t9RsOz6x6NKXeR+BW60uQDkFJtjUSwYMGPR+YULg3e+RoaT"         \
    "OCtaVK5+t8PrS8M/Amu4udb+RLlm98E0xFVZa+IEOzF3i978oV5Rx3zXv7tCgkH3"         \
    "eBO1cPHC9mL0ODerb7ldxfg+gkFAWJKjHIexUUvez7gOIHA9zt1rdN1N4Yj4tk5/"         \
    "vBF2E8vkG+l1t0wHCeso7/iGyhKK8VokovVehhB5t7bC2P0QiU3ctpO01cJcRWGu"         \
    "ftodfAYhWu6TBm4wIcl6/BYyUtMezLiqJMwinXyR1Uu072iOZxisAaH1qoZtJqAU"         \
    "PDjT1wzFtZl9nQ5I4Wh421dhcwiBiAfMf6KQ66w38X7P5FhGmF/SfTnKHLWYCZ3w"         \
    "d2OofOfcD4YPj7krBwSdrAjKdwzLXjkr8zCadR1+esVFPATalZvjg6jt0UF6oiqa"         \
    "MtEGI4JiaVuSjb9xu1YeJsz1tKcfam9zHaURblm6SJdoEtxCFhUqIUR1eRHXDotl"         \
    "YkLZJNrIaezBN+ITyNMrlNgos64Aq3QwVuNHI8DpP1k3h+nSKd25bZMQaykz3QzB"         \
    "Wlqeh3LM9Ek3gp8aD/BlH29QWiv9jrVBvP1h6kq/IPNJIYi+lcQzra3wBRDpew15"         \
    "N+ldN5XXYeBackFrf6dQQX29EiJJn3Q5UDOtI1WOf/g8pOI5ovsJ80WLsEI1pkW6"         \
    "jCTZCs79OAeV97vVUWha50X+Lit0iTEJndRVzT3QuZRDZdk0o0rBPSNxonRwy0WP"         \
    "0R895Cm41AURrAkb6suFrFzFrWN16tI1/rNGLvukFeBZoZBccw/MiNlm+KGx6Kn8"         \
    "0jxrCPHgATsIetanFbegGZuJfZRbcY0uyqJPUvdxqPKvIdv9qtaq+4ta612yJo+s"         \
    "c1rTzhqgV1J+jJfLLjWGNUBJyH0A1BFPo1a75NV2Ie8UBfN0HbfKRKq8ZMUp0q7A"         \
    "qp4gufgM02LY8I7UI7DfGafi9TSO9ciINvcH7vu25X/HLB/TnQ2FdxWRBYKeLwE5"         \
    "NRSGkG+dx1JzKryYNoMJcaWHVR/MOSO63QtzLeMBUS6Hw5VIzlJ9V0aao7xrtMnM"         \
    "PUzZ2Jt/sAbBpI+DNH0HQf6nsDjbLTKeOaqKeb1bQEjpT65b9+i1eLhuWJ5nCasb"         \
    "K2j22BeI1f3WcARXiLUeFz11fBM7NdRRm43WcDkjG8PJI++lKgn9809XzFhxX8HS"         \
    "bqRlJaTr/IrYcc7Y+2VQlNpZRT5JpLboONaA+lK40QfAhysqZejYOfxvmWfSe9QK"         \
    "3wYrt4ye2vHX1GU8lbc5R6WZFGwnwmpx5skwP+MJUakJMHqGnSOnbqt95Gz+/3mA"         \
    "uy7FqO0ttKXuYS1pfY2wmqxhZv7LG3hC83J8NhoX45QFwhS+njYuCVQMoqO2D1i+"         \
    "Vvb2aK9y0jJcRzsnwFP2vhFKftbg+pnUdV9/vUdS6bIw/HYYisS/HpKzLS6GmWJs"         \
    "oKNMDwF8G8CogYJ9DioAh/b8Xc2a9m0gB179PU15rzlDz72MNAtLTrRUTW7jJyBl"         \
    "vogAYM9Hvy0f/O0PjDXCn2yd6/LFLABTTEnQeflHX7VzkkQPhiCgc3+27MnjmUFE"         \
    "Oy0X/Ez4m1GHYQw/HTBEMePJuruN/sssKk4+Klt4BGIaghbS2tJxSwE7+/4mK1RR"         \
    "9ax5Usu/Vkh8oxi6MmXpFXl3NJ8DlGkVhMoMSJRD9JuCKyxlQl99g0LiOyVdOOwC"         \
    "BcCmFvg2T8Ex4WH9pdEljhQZgd6UfOW8Dg6/EbRZpAgBtqEwa5aEpssYNI45LVTS"         \
    "VA7pGpF0CuzS5b2mCktT9Dg0XATElxVO+pSczpZzISi0d8w6sFZAWQDEA7glGA1k"         \
    "Ye8bpV38yf3dXxxln64+XWoO7SgB2lMtzRmvi5LaLVP9OsRZTdcDi2zI6/YZlZd+"         \
    "UtUSvKaNK8WzBf3x34JxKqYpyeI3DK49CKBcEQxcN5sbs3nJLHX9Tkm2jGpwBvbR"         \
    "Z1PD+e0hREE92i091mV7BxR3vRmlmoF2+BkeQZDy8mNAl7cY4H/6JjGpRyWQDISE"         \
    "ZxPFQ1KsebKJK6MoBNX+PKfpQmJta7F3KM0IO9OXX7ssRjBFGWw1DEXBOCDIkBJD"         \
    "zQyTtProkpuQYQD89dt1/TtgVtb2kxAMuhwwm4tAKJau/LRiMC6F4WGc83JEcrdE"         \
    "8tXMh16O4zQuJj3e95a6BdJLK98Y76uj8wwUfp0ZdV3gudsk4OlJML4ZzWmjVrOm"         \
    "mPW78+/OEluAtreLH5Sf5VnwId4hsFmGsKaykicJO2UV1e+ttl1BNJxg+9d6I0aN"         \
    "kLSEjsWe4RYcVEii7UmSMirWrqRF2h0rCaJiWD9xYgvfFVWZDNQr09vSKfIWFkOu"         \
    "NBbU4dpVdhREj4iI0tl7xd2uBNwxu2pyGtZQ6HaqYSAnofQxJ68nptzQGg8ho6nH"         \
    "ksAoncLxrB1nI6fEVnVrwHXSoHx/pFG13Qigy1xMOj44e+CPuvXiuhYvFjFVZYCr"         \
    "g8Kb5t6M36GbC47ER1Ymwc4gLKXUoRrPb2pfDL3X6ZD0J0WENgSqs3c1EjqF83EQ"         \
    "ccCvPhQ0Cl9RTd69UU7lFXJB0zXNVO3ko+n58371x+aGW6KVflzn2fHy1yhB4eQk"         \
    "XsQvvVaPuARzbgCIln2me2I2SOeVIf1RVHir86PoKrLXqHIWGWkRqqbWoO5hz5S5"         \
    "UKVYzyDuOt4WaFSCxaxSizu7dx1e3I9iNVWVEK0RlTsN1VRbUm2XI3Y5u5Lfu8+n"         \
    "jRjiWkFpEweUTEfjOoR8h1nUoI+b9DX1hKVpXZT8Kooa0SsgmkHO05IDixmmJoU4"         \
    "nuyhtO9RFS9aswvwcRpwxruuE7M2xX2yJUbspDVQ9UYNF3FXKHmZTIEtsq8AY/Aj"         \
    "uDSLAsjJAdUPYpAzGLHwIpOHdgQVM0psqv6sRcqZ0VqUWleZui2/L8L/YhDSvA0h"         \
    "xSTSw1y/tc3kPMganvEnOKqo6+YapNY5/3ZzUm8zK0UhdY8op942iYOEa8vRP+rV"         \
    "atuqLIFs8bnKt/PAiu94p/uUJ/2iO6ZzknLJ9hxS0QGgu91eQ9CNTxNGQ703GNUe"         \
    "8BkT/ZeDx1d2tLrJKcqKPMJCDKeA1dJ5bmaAL0wV4yqYFcr2obBppkJyO59Ecy3Z"         \
    "sjDWHLprD/I/JTyXXwz5G1blghecDxk7ZaPJlxF5Vwep3RlDiXDxtPyDFBlzSa58"         \
    "QfQ9d5Vf79wYp0XOkUFXDCt/FKvWajLkKIBC39EV0jCi8bCWnIRqChwLZrsry5Nv"         \
    "4zVUZUHBOiEJsoHNszKY3xadJR8dsKSKvhiHvl8YW5vclxMusMRsqoPitozU1ch6"         \
    "EbuTMXeHfLTD8jH+ZfO5t8SoIXEYVVw2S8SXWsriSzeiO5uw2xgcQgsSDpppzDBu"         \
    "QIG0ohKwGKiH1t8puyjjsymJrW9Ygfy9enpKOERVfX3feh1KWa2Bz0iUHay/YYaG"         \
    "GW0n+qwQVxmvkgNdNeoAfOrKaqn+LYHyaic35kGLTb68bvVoQ40livx5OfRBt7Yx"         \
    "rx529vFoWMeNdgiK8UOxLmTGl42+oAnvCpNNtH1J/iQbf95SL3HkxPzL9cRWtWW7"         \
    "rUh/Xm3FF2NkfakpLcxoE/G47GC5bCvSuJ+wG5JAw363MQkXnYkfUvtGWCIvhMRi"         \
    "QnggV4xx/D89BoBseycCzDhOhMPlnCeRKjqG4U8c+n8wY9SPj4a8aXLP77soHnMU"         \
    "ytx/QH8SLQay3Op0cQXfjRULrmik7EaEzV9h4cuJhioLfYwDdTLD9rBE9F9jrMWn"         \
    "amI/HgU+pOX86PZgnbzKaPiKtU96SkYV/sdfWnHcuqll2nCLJFXp7ncBE7O7+nLg"         \
    "kQlh9gPcSKjoEGRhVoVPaUqM8BTzp3T/PX5bGkR3eyegpN+Mt1Hn2gaX31d5wrjF"         \
    "hEm3MfCjRv6EPHOii3mdaF+H4m4fXn4G6l8DQz6NAYwrS1xxe6dwFHd7O5Gn7GG0"         \
    "/oFd5Lf9HjZSqabROf/Yl0jDhY6idDierTGDJppM/hg8c9U/FOoJYN1hhuHckB8v"         \
    "BeXlRHxbsawGOGPg048WzOxaPvkElc5BP656aqHP/Bm1FZZeZYI5zQF1TexKsRBJ"         \
    "yEM4H9XDYz4YM9my8oFJTWVbRhH4XmnUyzrK4qTEv2gmm+aeKbxQT1LvODn9REm1"         \
    "LalYr84OywkoooQMTZuP7WhXc2CRWqIWMAvyrIChCaZS8BoGjvO3kdTak0UNXlGU"         \
    "q5AOrvgz4nePVx6lZy6EkLH3oq72gSq+E9NUCWp5clI64uBXBUW7AtUycoJZgdGt"         \
    "A17EDNHqLMRvupU31rPv4cgnRUqcpAP1sp3ZNTXHqfgAwSyGIAJc2JcUv/06rWxX"         \
    "qzoZW3C0xM8L7i88SrnN3BwP9xmlh5rxDbV2eOkJovOAOtHRIbZZ17nWx0EcBv4J"         \
    "fsatKxFx7SUiMnPqsRs/04+NogQalbFQZy0HJWBveegNcGUfg/fx5WFe+M3xerbF"         \
    "qc4NrsEmFUH2Xhtm1bHAw8s7iAUcnZiHBgGjBaRFhvi4XqF4Uy96H3g66KxL0bUV"         \
    "TgctYolllAFQSkJW0ms/YOctzJJfm4fFB/RRpCm3N2JeCwPlc3/MJLOxmSCKB/cY"         \
    "ZXc8liIncsjQeHDfMxuWaKE+5Bzw2y4x5RklTd3gWbBfXUffzoXkBs2UK+jUmrCm"         \
    "WZVBBbaUgyMmH38O6I8xWqaCyyo4zq1gbdIzKD6UrPSKC+fbJCWkKpGOO/DWj7Pb"         \
    "bQnNZKgQCtShcUnCbDkiDHosnt+DQ8hmaxK8zdti78BCN5oOs6SXUwQ74+KfpAsl"         \
    "SzVfZkElmroiX70MN5fPH3RPiqi3FtB6LQ6kWrrClvYKb9H/Ft5BOaoooQUKRXGH"         \
    "FuRC1xoyHUu3S3z+sNyRVJE2V+rI+PYO5ZQckJvZoWhbDsPvH4lnOQaIVc9TpKvM"         \
    "zaKTkJPoydWAs9Ff98Fv7VquJBGElICn9jvswSoVF9yFR3FUcJPiKRvcgRtGhjEk"         \
    "e+/XQpGSSOhKMp/schqYku9S9r9CSBvu/Hc5ZHmqCBh3f9eXb4Axr0jOdnIHWrqT"         \
    "eHqWIfrnDMTqqWsMRUbFsrkEdrBls5w1v6lSOIo2ZAT/RvPJvHRQO6xJlUEblhky"         \
    "OFRuffBf61lMM2OQGf6qFTi9q/suTW1/cltoraCTqwnecKTfFz5gcfWfbrZl3Ue1"         \
    "H+cMpBvdpaApbRt4mPHdACVeamwH1ezpjl0Iv63B3ZwsWm7HQ4B19rNDNT0ZnNbZ"         \
    "Fc9uqFfd19BgZPiBheihi/GVJgcaDbUpkjGhD6qLvv8fUViK7s+J7Tf/m60vkOEy"         \
    "GgfEekXBz8p0jcvk0w/bqNgarY2Vb0QMlRzvWsRlWI6WkWR/0IS3Ux6mIcRSJdt2"         \
    "dsXSTeIP7ItwpHnH+piO4BKb6By+nzvPs8PPScpS2ItFETFR7ZW21ceMQH+uslGU"         \
    "wqOOsnrEapC+POouKRUp+B2sm41F7lVu/B089aF1wBBpstEkHqfOoDz6Sk/OfMT8"         \
    "pRRnVTQyjXFnyhRdM0chU7e9T37BprJZ2NcNar2ylRng8EL/vf8glTe/Rs8L8HJm"         \
    "yOmHPN/qYICauKA7DpQ9v6FnnDWvBcSCfWZlinYlgYU1qUYKBZg90K/cweIFOwgo"         \
    "/nPVVNcGjoDvoSe9Rakso2QwrZNziQS6yzOXGVbDxoy8g/QMJhfeAUexKRVQZ3Ik"         \
    "SWF6EVoBFGkSh5AowWMIVIzELoPss8X0npuna5mcVWLQMQu0VmhVLOR+qjytMIJO"         \
    "e+JVGBeJJydAvgd4EYR6aajJRdr5U2s0HeSD6OLexpDa8Nzp4YXsRvC9ztiO8rNH"         \
    "biUjk9kpeJX0uvcLqWzpEgKej9NwfDdWQ25GoSLQwy8nSJoavPnjx+fZP7zEoOa1"         \
    "tacO9Oz49YUfPXs7TpI38kIu/qly89NzYxqT1xxeSdCcfFZ+adn67FsRfIICK1Fm"         \
    "CJS3COnEpKj/dztqq0WwHAADsx2KUgAChKR4P/eAJFdrGlMmcPu9xiLNpg2R98Cq"         \
    "IZ/zCyZigRDoJKhZDKbrRBWybwjOw5RsNAS3zM9iUmYOEpaorQ5EaGKRNY9Bv8pT"         \
    "tyHbNFktdVUvMiKuzPeje+GlyxFszrWV86R//wJcHeVXL1+ckEnGElmXt/AR0G6o"         \
    "RPGH3yl4z+wbRYEtF0VpgQ3XsCyThHtWzdx9DwPyz3VpeZFmH3I8CPJ6pPxWkVnX"         \
    "kNEjYs2cq55Eho5P/IUJdrf2hYnU6I/HjNkhEaWBNAWOu+NyhLmEv1OgzAMhSSs5"         \
    "83SITsWmVaE+SH5XjpxIVCsnZCCPFvBvp+cGcENY9gyw0KZS74Yu0ezJnavnNmEK"         \
    "+61FE9cMc1DmAkXIaPkrj63EDVJn8/cJzy1XZyIPhCw87raqCb+tWskKEcTVwAnl"         \
    "VSjaH7rdq5xyHmLXbyg1YQsrcAxo/sLqgSRP3r15S1e2C+Oqr7tcoI3743AKLWLk"         \
    "/vu/+Vh7SrxPuHzGCaHXwV4gNogxc5n/dGtH0YKz1fYD4/fpjaRKv9XzZHHaYBpx"         \
    "psLH7jwTpksYu8mu939QmsaH61Kd/elVWi4a21N/WwcsW8uiQimaZAzQRCxmAA+k"         \
    "PyhyJ3yVQWraC43Xi1fHEu2fdoRbvT5+5qpW0p8zxCXXxDH0cVPdBaHN4yk1QZXV"         \
    "q7i5mcfWMGzayK+DjW8rqrXH2npSjFcwkC42NGfHw/KdCEQmlTgTQY0+wVIe5agN"         \
    "l+FOLF7K2tToJegWLugujlyxH3sA8OyDPV5yovKdWUnFJFMBkh7HZOFu7VeZChxa"         \
    "nQZYQygJJnfFdFzyzkBXJoMW50e9ZqYtp/PF1IilmKq2adj5RtPB9xJ8cDACdZ2q"         \
    "p/V4a28aWSKAYUggYuj5n5mzl0+Ur39II1sA8aVGndZKnfc0TQJ21XiuNnhjwjoh"         \
    "qPjRD13yQb80eaxp2XDfJCjV9YRdZ2tcrwYaP6WSxf3KGKVHSb2ObTVKoR9BqbTW"         \
    "9IoyiLPy520slvpOhlqthn3ZSNjgcTI+9m877Ubmt2uRnbH809/EXOKtspoN4jCk"         \
    "D0phHn90pYdTh93dbh3OBq0j45cr+M9x7wHNSmZKKf52+oB6QlJU3An4NLJTlSQ1"         \
    "sPhqpJhTgW7Xr+Ol3yLrwGn2NzI7aRmTBakszUI7GgveCVz/ofkFYRJBATSNRmlE"         \
    "CwL+VDJhYBIrdwoEm5ETMY2r0s0yoIqIoXm4/3sGX2RMwNUzSREv1bg/btcsyTOy"         \
    "TGbW1ryWPwfPQAwSozfywYSyj1G4OZUAr8P0whgJFWF9YjRPAuMaYoX7w4Yfgmjx"         \
    "5SxXKk+4a5eueueabDfGe93K0vERoFmUgSAEctjfGTbg9VqgwgcQgC1ssazBQQx8"         \
    "aoSymxBjXMs6dZzKfqPWbbG0xt6XIz9/5ApAUgR8MBrExKPWYtmWzo8z1WLi/NUy"         \
    "zOwxdyIzaKpQQD9+HEQrh30lpIXm6309pWZLpV+wQrYbdqERSWn7tDO3W4fdH0CW"         \
    "Wl0PuIQXxiQLgq2+/dk4NiAV5bEqAakomnl98ZOT3jMKSkhqE90n2Rj0DcfLTTZw"         \
    "H4PtB14GPaw/3kHNV9htaE+hiyEPgA5SCeNf3gsyn1Qyx4W/0Tshekh9R1OTdk88"         \
    "9cp+tiHEewKl7mgOSXd/Ux03aEplmZWVQrBv0JAFSo6xfR71RKMSTKd5WhuS5m6A"         \
    "kdY+UNDYlcysFWkyUvz9JmPrfxclUKGwiJD5p7RraX1zL0nH4GCTBpwPGy3FOZ5i"         \
    "GsJVXHb0tRZiXB8R0cX0l4pXOtjvcpEViSs8wAdNekrJEVBFHYNMfHq+kQw6fiz1"         \
    "0Hxg98qyXFNDL7zg4Oqc/HchJcUVfYJOXm8iTSu5m0S0c0on1rA2rNXpARNNBuCy"         \
    "HoDR27JIeHjSyuiLWNjCBFzd/MNZnixq8b/twLzW96fdf8jrh0V30OzUB/Xru5Gy"         \
    "YByggGMIIEoE72M19cou2+vcxV8BGcIEy8jHJ8x3vnwSiY7/GwvgHfgF2WKcOwk3"         \
    "tA1RMvLJO4z+k7+SRqJ7/KZdUnj5JXgbh5WBdwauOJgk4OOLdWoTzfyeUZ8jGpAK"         \
    "C+O9C2rZgp1gF0TT3GM6ny9yu9EXLi3fvtnPCp4FlqG4QLY+x4434F34wAmR/4iK"         \
    "Pf6dde4LhXT1Q4CIOKsLZGPzMKtfB9qAXAy/4OL5zgHyWF/Wa3z7GlZ+fdbqWEqe"         \
    "NVXFHj7FtW+P4vqJiteMYAD0EUafoZZZzmdoj4tdeI+mJCO26czL/Aeq3jdxtv6v"         \
    "RPMiPHGJBLv+N0Tgm4VQc7z2GlnVuSNmqViQ"                                     \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif
