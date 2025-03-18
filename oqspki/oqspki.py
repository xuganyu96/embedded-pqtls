"""OQS-PKI: public key infrastructure CLI tool for post-quantum primitives

We use some ASN.1 encoding:

AlgorithmIdentifier ::= SEQUENCE {
    oid OBJECT IDENTIFIER,
    parameters ANY DEFINED BY oid OPTIONAL
}

PrivateKeyDER ::= SEQUENCE {
    version INTEGER,
    algorithm AlgorithmIdentifier,
    sk OCTET STRING
}

PublicKeyDER ::= SEQUENCE {
    algorithm AlgorithmIdentifier,
    pk BIT STRING
}
"""

from __future__ import annotations
import enum
import base64
from io import BytesIO
from oqs import (
    KeyEncapsulation,
    Signature,
    MechanismNotEnabledError,
    get_enabled_kem_mechanisms,
    get_enabled_sig_mechanisms,
)
import asn1

PublicKeyBytes = PrivateKeyBytes = PublicKeyDER = PrivateKeyDER = bytes


class KeyPairType(enum.Enum):
    KEM = 0
    SIGNATURE = 1

    def instantiate(self, name: str) -> KeyEncapsulation | Signature:
        """Assume that name is legitimate, return the mechanism according to self's type"""
        if self == KeyPairType.KEM:
            return KeyEncapsulation(name)
        else:
            return Signature(name)


# TODO: the OIDs of algorithms are not standardized so we will simply make them up
ENABLED_ALGORITHMS = [
    (oid_int, key_type, name)
    for oid_int, (key_type, name) in enumerate(
        [(KeyPairType.KEM, name) for name in get_enabled_kem_mechanisms()]
        + [(KeyPairType.SIGNATURE, name) for name in get_enabled_sig_mechanisms()]
    )
]


# For testing purpose only
class NiceKEM(KeyEncapsulation):
    ALGNAME = "NiceKEM"
    OID_SUFFIX = "69420"

    def __init__(self):
        pass

    def generate_keypair(self) -> bytes:
        return b"696969"

    def export_secret_key(self) -> bytes:
        return b"420420"


# Taken from https://github.com/thomwiggers/mk-cert/blob/232648ed7bb73fa286969e94/encoder.py#L201
OID_PREFIX = "1.2.6.1.4.1.311.89.2"


def get_algorithm_oid_suffix(algname: str) -> str:
    if algname == NiceKEM.ALGNAME:
        return NiceKEM.OID_SUFFIX
    for oid, _, name in ENABLED_ALGORITHMS:
        if name == algname:
            return str(oid + 69)
    raise MechanismNotEnabledError(f"{algname} not enabled; check ENABLED_ALGORITHMS")


def get_algorithm_by_name(algname: str) -> KeyEncapsulation | Signature:
    """Return an instance of KeyEncapsulation or Signature according to name"""
    if algname == NiceKEM.ALGNAME:
        return NiceKEM()
    for _, keypair_type, name in ENABLED_ALGORITHMS:
        if name == algname:
            return keypair_type.instantiate(name)
    raise MechanismNotEnabledError(f"{algname} not enabled; check ENABLED_ALGORITHMS")


def get_algorithm_by_oid_suffix(oid_suffix: str) -> KeyEncapsulation | Signature:
    """Return an instance of KeyEncapsulation or Signature according to name"""
    if oid_suffix == NiceKEM.OID_SUFFIX:
        return NiceKEM()
    for oid_int, keypair_type, name in ENABLED_ALGORITHMS:
        if str(oid_int) == oid_suffix:
            return keypair_type.instantiate(name)
    raise MechanismNotEnabledError(
        f"OID {OID_PREFIX}.{oid_suffix} not enabled; check ENABLED_ALGORITHMS"
    )


def generate_keypair_bytes(algname: str) -> tuple[PublicKeyBytes, PrivateKeyBytes]:
    """Return raw bytes of a freshly sampled keypair"""
    alg = get_algorithm_by_name(algname)
    pk = alg.generate_keypair()
    sk = alg.export_secret_key()
    return pk, sk


def encode_algorithm_identifier(encoder: asn1.Encoder, algname: str):
    """Encode according to AlgorithmIdentifier"""
    with encoder.construct(asn1.Numbers.Sequence):
        encoder.write(
            ".".join([OID_PREFIX, get_algorithm_oid_suffix(algname)]),
            asn1.Numbers.ObjectIdentifier,
        )


def encode_pubkey_der(encoder: asn1.Encoder, pubkey: PublicKeyBytes, algname: str):
    """Encode according to PublicKeyDER"""
    with encoder.construct(asn1.Numbers.Sequence):
        encode_algorithm_identifier(encoder, algname)
        encoder.write(pubkey, asn1.Numbers.BitString)


def encode_privkey_der(encoder: asn1.Encoder, privkey: PrivateKeyBytes, algname: str):
    """Encode according to PrivateKeyDER"""
    with encoder.construct(asn1.Numbers.Sequence):
        # NOTE: not sure why this is here? copied from
        #   https://github.com/thomwiggers/mk-cert/blob/232648ed7bb73fa286969e/encoder.py#L198
        encoder.write(0, asn1.Numbers.Integer)
        encode_algorithm_identifier(encoder, algname)
        encoder.write(privkey, asn1.Numbers.OctetString)


def generate_keypair_der(algname: str) -> tuple[PublicKeyDER, PrivateKeyDER]:
    """Generate fresh keypair according to the input algorithm name and encode them using DER
    format
    """
    pubkey, privkey = generate_keypair_bytes(algname)
    pubkey_encoder, privkey_encoder = asn1.Encoder(), asn1.Encoder()
    pubkey_encoder.start()
    encode_pubkey_der(pubkey_encoder, pubkey, algname)
    privkey_encoder.start()
    encode_privkey_der(privkey_encoder, privkey, algname)

    return pubkey_encoder.output(), privkey_encoder.output()


def bytes_to_pem(data: bytes, label: str = "CERTIFICATE") -> bytes:
    """Shamelessly ripped from https://github.com/thomwiggers/mk-cert/blob/232648e/encoder.py#L218"""
    buf = BytesIO()
    buf.write(b"-----BEGIN ")
    buf.write(label.encode("UTF-8"))
    buf.write(b"-----\n")

    base64buf = BytesIO(base64.b64encode(data))
    line = base64buf.read(64)
    while line:
        buf.write(line)
        buf.write(b"\n")
        line = base64buf.read(64)

    buf.write(b"-----END ")
    buf.write(label.encode("UTF-8"))
    buf.write(b"-----\n")
    return buf.getvalue()
