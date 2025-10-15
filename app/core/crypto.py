from pathlib import Path
import jwt
from jwt import InvalidTokenError
from cryptography.hazmat.primitives import serialization
from app.core.config import settings

def _load_private_key():
    return serialization.load_pem_private_key(Path(settings.priv_key_path).read_bytes(), password=None)

def _load_public_key():
    return serialization.load_pem_public_key(Path(settings.pub_key_path).read_bytes())

def sign_vc(payload: dict) -> str:
    key = _load_private_key()
    return jwt.encode(payload, key, algorithm=settings.jwt_alg)

def verify_vc(token: str) -> dict:
    pub = _load_public_key()
    try:
        data = jwt.decode(token, pub, algorithms=[settings.jwt_alg])
        return {"valid": True, "payload": data}
    except InvalidTokenError as e:
        return {"valid": False, "reason": str(e)}
