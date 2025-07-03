#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "falcon512-falcon512-mldsa44"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIHajCCBMmgAwIBAgIQBEuTQsB69CLki9PfUtPrwjAJBgUrzg8DBgUAMG8xCzAJ"         \
    "BgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAhBgNV"         \
    "BAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVuZy51"         \
    "d2F0ZXJsb28uY2EwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMIIDjzAHBgUrzg8DBgOCA4IACS4s3/P9SYEHgeJK1B63WW2t"         \
    "5C5Hnq2cCPHG7224dPhWrYpMchbb+KTEqETAmiNz65ZkJgQlN5dcrKGh6srFr7Em"         \
    "5UVKkMoXAUVkql9Dulq+ijbvuC7eAPW+7HhhuHQwkQuFU0awosyTc7Dua9hrnqcf"         \
    "YCWT9Q6Rk8YDkZ2NSoqyVPpZxRQcnnMabMSApokoY1tvbk9pfpN5nR5j/Xl7JJ0j"         \
    "ZpWBaHXKv4TQmYLMy1CXjBpbl2bEu8GyQauqRAU2OUooB/Ffuulke1u2A0HTJksS"         \
    "HyROs3LnADSQcmbHQRX5eX1DEzwgA2SwoFjL0oO0BsL6zsI/fIAHCl7p4KlZhZUK"         \
    "IlxHVhCFCUB4nFFGuHBeZq4oyuYoapImzickzmtxJELrAq3vAHAp/nRZ24cGnkjn"         \
    "YZjPoL5D4yQhnLuwq1kTauazjkkUUpo6nnSi+Cqc4Egd94ZPU/yleX6KeEWfsSQE"         \
    "wcqiW2LKF6MqSik0jAzl/KXxQMh32KocVRvxEHgDR2YjRUFm7NRFPyH/BDia8rDy"         \
    "gXGwTysjQrQxdi8LBfK0JlyNsqZkzwVg6JKCtlXJZWvENAWNqVgSG4cyNmNmpCk2"         \
    "7ciTa10/WeQNdw8UfC4N4xANLi8RYWZiWsNICBpN1GVBnx7WMtHRB2eojZ456cPE"         \
    "vM6AYr0Z3DzCVKWenGWJOtQy+0GIiJAh+QijqZ66tbBrDGGFdmCLOiNuORm52dmR"         \
    "XpPJcXrFBy+XcZW3iWtFuSTRBxvu0Cjw4xYeDQGfZUTylW4YvQLW4vQu9gt6fMtw"         \
    "1wkNmeSVZqjiM8gFGk1OWK9e9XEOJpK3xNhbNdgyhDaj5IOlih5WztFvqRyTpI4C"         \
    "5kmNDbXfaPYhYkUSnVgmHtuauvCJduMhNryFhFvUyiPlqhT6yBkbVv/BGCpfW/y/"         \
    "aeaqbzcVinkQZhN9zNZa/il1s/Lnkscdm6xhRGS3IW+O4RrRp2okhUiCom4ub2/Y"         \
    "keSeSK1fMmOW/2TiN36PIknjrR4gZVqSLdmDpV+QxIK4dZgyy+oAlKQu7WuBANOD"         \
    "IlVbRQVPmm7qt7EeoG5R42DukEMi4Yapweb6cs4bYMLGyJuKccfiw26EqsLlrSf1"         \
    "gUYckwGUHY/JhuXGTVob2XMw+Mm1lFAb4Z6oBSPs4Fc56a+gvKayT8dyGtTgJUJK"         \
    "ECfoOUh9V/g03o0Ffm59oxAwDjAMBgNVHRMEBTADAQH/MAkGBSvODwMGBQADggKO"         \
    "ADlZnvEUZhfmrvDO/eN9O5NsBLDfMeQscL5jAmIJNqUdUuG9UJTaQ+puvOjjL9pn"         \
    "H3nz6rey6tdtXmxavFyOsWGHFd2G3TvhxvXSSa5PQ/nOZp0mFaZOMurZVYqp7mYx"         \
    "AkkQjKGQjwrupqvyTGEFgq/bbtIoceORsrWHnWSMLKiOeh6k/HiCnIAcN6N+tKFs"         \
    "Ih7Km7NRCss4mflf9Qz3KYkkUVDQeS1a2T2S+arPFd8s35WrI9er9OJs8cE9DfZR"         \
    "GSi2d5YdW02oGMwhkja8vYHqYpgiUNMTqaM7J8lG6Go0Yw2OlZrv3PSZMeKDuI6c"         \
    "zGMOyEhg2KQgrRhf326blriotS/OKtEtUqQHfS+Z+Mxbu/JI1K5qO1eMbqfJL8ff"         \
    "WIAlBwI5A+l30DY3O2FBGHZmML1RaQt3um/tKtIZk7mm8BWazF/Sk65LJoU/xCj5"         \
    "2wE100p+2wamGzCu3jnRZtfUZrGRjXYZsyZ3ayIqiaGXExubw+ZO/ROQ8sgaI4Nj"         \
    "H31cMNCiXh1zNF6y8BMoQNVr7vEZH+oUBnCy5/9udAOpmYAYpzcUgGOuD0IauOY+"         \
    "rF6azGcn0Xm2K1/QsrrZ/1n+3XhSycZ+A2+aGH9DSqP8VP3VeqH4gRksN78a0mCr"         \
    "P4IIiznk5z/CUmokK3+XKzsaA2RjrQhWYqLTnWT8rj17PLYQ3e42D944+vAj2p6c"         \
    "b7aSKHbH2jWqhHZtKe0BRkGg5Ri6O7X3XmvWahaC0+jYLz2M1hcVnqTmNqgB82Xy"         \
    "DsFSb3osYmDHYS27F/4g71OgSOJ3+Z9Slhqan3OYYZUdjU0+y0Vu86eXDQCZNWI4"         \
    "b+H/YbivzBQ52aIw351bkoJFb8uiDaRFHVpe1byA"                                 \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif
