from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64, json, sys

def b64url(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7)//8, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

path = Path(sys.argv[1] if len(sys.argv) > 1 else "keys/issuer_public.pem")
pub = serialization.load_pem_public_key(path.read_bytes())
numbers = pub.public_numbers()
jwk = {"kty": "RSA", "n": b64url(numbers.n), "e": b64url(numbers.e)}
print(json.dumps(jwk, indent=2))
