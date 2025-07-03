#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "falcon1024-falcon1024-mldsa65"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIINVjCCCEmgAwIBAgIQIdKZWK026n/htVdrZJ+amjAJBgUrzg8DCQUAMG8xCzAJ"         \
    "BgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAhBgNV"         \
    "BAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVuZy51"         \
    "d2F0ZXJsb28uY2EwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMIIHDzAHBgUrzg8DCQOCBwIACoSYIoPZHS06Hh+AH5vSpBjD"         \
    "kdZrHI+qR5UsKwwPHetL7F7eQhSDuQYgchZm/UXnHQmOjDeGdEhJJAjqFmSBF5zE"         \
    "k/mtEbg/MAaLim0/YXUixGiFlUz0JzJK6k+Mvl+j7FFbJ3grpz6ROaEm/VIMR0QI"         \
    "+IwJhtE/rcYfMwIdHkom/DQalCZlDXonKAL1RV2z5LNWiZcZX9CCZ+lHuKG7euT7"         \
    "N6Zw8hKsTZamRGKIkKOiVC/jtYAgvDTnpNKQpacRlGiL2chKhjBmLtRUhl1A0ZId"         \
    "ER1sUPts76EuOr/KBpJ2qLILGrLM0FOUW9FMIt4y2uiBz4IRCnW8EQhvXWplDSWE"         \
    "yFENAJbRzt9DoYUuZp7jQLCs3MqErEGPIKhYhGfjKnKtU7/mqEAVq8S+ZVNSVEMR"         \
    "T65OA93l0/0e0YoSNeq2aDtXYsNXNVCdYby/YJ2FlV0YTGrkLX6jOhRoypinVj3u"         \
    "h+1m0jI8QmU2ksVEOqO1joiBXmj/+3QU0n3YmZTzUhm3NHEZd6/6Seb6ZmGd4pwx"         \
    "SrEQaexfJkvAqw7hAETeay1NigbUN5oDDuYM8ls1NRdiBhlQxSdYLwRZTNSFHKNE"         \
    "1QIVMmkRP43gd4NX2bRACCFWzcVU3fNFJMqJlwzQNYoIfjM5j3hM7hisynupmAdQ"         \
    "rO3mBgtd9XAJXpt4kbIfXj2J7BhEp24Q2RdXDIvSvqVpTdNN3Hgw6gp1mSmmlC7p"         \
    "JF50SgPY12snitGjZItwCInX6luFCiJNKEoUbJi4urR2ukGyARCJyYslAyJkPQuQ"         \
    "VAiXTmg1c5v0MiEx4vtKu6N14NPDRL4yDY2i180PuthOc1RfNRqm66edpjxAvRZW"         \
    "hchrcIjqmuhLGLQsIoVMzh8x5L6xL0yDtPaF+TLtBnhqoYp4i+NGOnQS1IJXtDiy"         \
    "iApc+itoATVVhkSD+BogPZe0J9U+EWljFpaxV1ezT2FU8WMn8F9wBvDIqusHQp20"         \
    "96HGUC9jZWvHqwnkliB+EGXCjSne8zStHQIj7lBBiW1iNZk6c6RWpWOsmrtiJfBp"         \
    "yhKjHRDQrKTxMnBq9DK9/aQG0/+wbZFH8uutQL5BQv4kYnQcFEIACloakGEL+2/J"         \
    "MJY5OVQLXmNZRJORXwQUQBxiHtN2ZdKfkKxeGKD25Cibq1o3dg0X3AeKphplWB6d"         \
    "Za0FL2Dpxp25LiqCJC5sJ7EaYIQmw3452wqmIw4hLK9IOB7tg6LSestFfIN1UPdh"         \
    "BARm9Yy0yGohb1LrlRPcOTZY0UJsJIaRef2Eng7kXLGLKAZcUHECi1qFiOVx+EsY"         \
    "jOeHcVoJWSnZGX5JNZntlxwZXvf6ze48udT81oWsE2VJ+8P57+GBcI/aE8uAmwFA"         \
    "1a2ohbKU1ViLEecl+gO3Qc+VO5xhKV0nTV6l1IupqtFe6GEaEI90WV7EGtkixkTM"         \
    "mNBVRGNv+eX52opDKYgeo1ATp0C9MwWuCm1vNSxAP4mUr8zhiNRDZi/cnGEbmXV7"         \
    "JUb2puBkDj5PlLygLbRGpSVYgpVIMd1aoektZZWIpQtnzlSFtBLGSmgmZtBhO+jV"         \
    "CNbBBsOfOnkt9ldWH8SnnK9pBZ4mGOI0o+qIlWPhFul7YY2+YrYE6Bs7YjSU929U"         \
    "Yh3Q6QFGqFdAdj03X4JwIXVx6LliYr6mEbf/VL2k/QQICdWBVOw6pXqf/KUp+jnX"         \
    "qWG9RE+nrGchgMYOsenZzQuUzpG4JIMqRXHTwaq6u/L8emGRrR/qshZWWhdH7YyX"         \
    "QO3Yh/R0leavfpro7JUkCcMHkAPgV8w3Mv0jVhoARoiIwAZqwQQuMn+y3cOoJcQh"         \
    "kgYSq4cWqOubCEpokL4Tv6JxE3DjNVwaxoU8dwFbYcqo/Tuboo7YJvSNdcnbQJ5C"         \
    "GWgpLEB38axiEwJIcJlFEcUKQJaAasuj0BwaRa6352zGLYm2UWhlRzMxJaKaKH6H"         \
    "aOQAs+oYcp3ocmSHv11Qq5TQ6cu1PBjH3FqRfg6MyYqIQQV5a5pD5zhZLbKYumFW"         \
    "e0oF1VZJN73UaKahFLFv3IjV1ocpLFw5dZsJACriz0B7ZwVM4ae1ZONavTbYOF4N"         \
    "CTvm3MNeV9tlqGhbsSckfC3aNP7rVDJQsnp0IB0UurzgYQeCGs7vSORDHWxwKwLV"         \
    "m2J+Pthhqq5wXg6wsrrYJLjwnGjIXQdTXqGkM+rXmanSlqJVejiw3buqITybpFYy"         \
    "qmnHEj79pMCL1Xwl+aSFE2lxdkS2cB5WPT1Ds3BvlLGK2IgB0CqMZmbT2UKWkyLu"         \
    "yMMe62eEwUBa6q4WQcrqluiNiPCwFpOsoklg8set6aGdhdd5V0RRZ9pUIVlXN47R"         \
    "ouR94Vq4HNaTMYdgqYC0ZntJW2PMskMVKQcIKAaAPdM1bJk0oUgKylYY6ejWWkWj"         \
    "EDAOMAwGA1UdEwQFMAMBAf8wCQYFK84PAwkFAAOCBPoAOig/7wmIz3D9y8xUHKLM"         \
    "uvELOvkmFrNqAAIA2n7a3JT7VEPJwIkUT8JcgigKwgtsWPEVpOrhImLm9PmWxxPl"         \
    "sEMO5Ya6o98cZPFh+3Ka/WeKPrLNmGWfCvfmEmSk1cAzmstZxrrssoe/vP+zkgG2"         \
    "5UNWVHnI92na9df1Jdl8sDioDxbG1PygTvet7NiZ82LeHOU6l87yZ605yYNSyKON"         \
    "GldLLqdHLof67/W0Fwnaelx5l4bLc6HTZSSsot74BUXsgDMatCaSZJqmDayfbx+q"         \
    "KgnEXRzvxYG5dxzouQPxVar9OQForNpaz0RrN5+72bXR8YQ1cDoWulr5SK75rzVK"         \
    "RUKhQ+bafLu+xyZkEfFXJUMbrcswdpqjQmXM4j25RpBn51/TxbRNPQfLS9BkWwI1"         \
    "yOTxBhMiQKK3fEId4jiHLVemGu7yKGQLxC4q/2ZZ2g5WiKsvFZNGairM5AYQgL86"         \
    "wkJDzLprHXFfR1jcXb2NU42cgOeMXrt96L8nhr4LqdlI4mr5a7ambo/et0b5lwYt"         \
    "9zeZN++wTu7Wh0XNl8QNKVFA/PaVWI9WEe1N0T94M/7Wvc0syLzSfXmzwu40Ns8+"         \
    "1ePLXOvhMs2yNBhyFujxKYPU1Krso5TVxlCkCjBU5wciveIRXFvr9F2Joh3aIfgl"         \
    "mmBy59LLQRd4Yjbba2rL5fUkwduaNdiGa4+Nf2SsK+Okx/rpxZKgWi8755MjACkT"         \
    "TXW7qmHXD3XexXLkSPgtLcqi0ZqkyWJHq3xte5mvSTfIx09l8RAOblmk3Jwqblri"         \
    "vcnQAoDr6x0uduzRc/7lv41Uvn+b3Gefu92aIpymNynFo0+229ZNo04g2SyRaDaN"         \
    "EtVw5N0z44U8aWC6xGzeErVttdAxW9yhVYWXZSIemc5hzxbnGkme+DJJakJvH36F"         \
    "RY3KsCRtmFFLgTHIRvf1nDG7s7YTk6jZGhcDRRGBbyCt6oyceZFoBpOElrAu3fpP"         \
    "XUKgW6mNYdFnpxlIOasyrjmcgEs1dtwt7yqrsxuJwVDQm9K2iSSi71lzzF2Hha2T"         \
    "HQwaLiJ6zfvbPuXUWaSb3aVvXApcujLeYbqaqCLHjTbf3JpS/szR9XXTqjEmh0zQ"         \
    "Tp8sP2VB735etyNykjqXE9CG0CZRg5W32qIvRAJ1KYRlZ9tUz7KTuZOibV/LP4l7"         \
    "ZoKnYeWrPo7GHVI2ihYBh2wZOpl9jLFQ04GOY47P2TLjaeYa1i2IwDp4faqEdV+r"         \
    "exDAHF9cRu2aLJAVZiDHT+G4JipJsKTi5A2bjYRJqZRiBFC6fZ+hE0YuoojK85ey"         \
    "uKa++F5rWqeQQkbOI9fsC6aFkDRZKnaq+s5OvRHnFHcXo4b5ashKgUqniTyZkvFj"         \
    "TlvYiyWd1S9bsLFUoCbjuHRGW69bgI3fT1DPY01zRRVKfLEz+WaJI1Rt82KQqjb5"         \
    "uWjzQeXPpo7CRjVrgREiW8zB1nlke8sN92VGba5ePBfqKLGd5FpUb5yzzYN8m9Rd"         \
    "eLwqTUEhVonFVS4maw8+SozJLT605Z547pmnEKB8McfdiVeq3T9HMn9jqkoqMYym"         \
    "0Z47OEbhDJMXdtT4olJrP6rBMYsgTAmw+nHVbJjQJVBLfIXTdAgcuT6oI21rnleV"         \
    "de+5fq4VKUpqtDIO3JzX9CPDEqZe/3IJ2n7wT+f+63bJxFdwaVQVTFJYrTvu3Z5X"         \
    "pzjfGTcUXSgokg=="                                                         \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif
