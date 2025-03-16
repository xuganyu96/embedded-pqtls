from oqs import OQS_VERSION, KeyEncapsulation, Signature
import asn1

PubKeyDer = bytes
PrivKeyDer = bytes

def keypair(algname: str) -> tuple[PubKeyDer, PrivKeyDer]:
    """Given algorihtm name, return a randomly generated DER-encoded pubkey privkey
    """
    print(algname)
    return b"", b""

def der_to_pem(data: bytes, header: str = "CERTIFICATE") -> str:
    """Convert DER-encoded data into PEM string
    """
    return ""


def x509request() -> str:
    """Generate X.509 Certificate Signing Request (CSR) from public key and subject info
    """
    return ""

def x509sign() -> str:
    """Issue X.509 Certificate using the request and CA's private key
    """
    return ""

def inspect() -> str:
    """Print data info to stdout"""
    return ""

def verify():
    """Verify that the public key and private key are a valid pair
    """
    pass

if __name__ == "__main__":
    print(f"liboqs-python {OQS_VERSION}")
    kem = KeyEncapsulation(alg_name="ML-KEM-512")
    pubkey = kem.generate_keypair()
    ct, ss = kem.encap_secret(pubkey)
    ss_cmp = kem.decap_secret(ct)
    assert ss_cmp == ss, "decapsulation failed"

    msg = b"Hello, world!"
    sig = Signature(alg_name="ML-DSA-44")
    pubkey = sig.generate_keypair()
    assert sig.verify(msg, sig.sign(msg), pubkey), "Signature validation failed"

    print("Ok.")
