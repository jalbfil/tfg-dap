# app/core/crypto.py
from __future__ import annotations

from pathlib import Path
import json
import base64
import urllib.request
import urllib.error

import jwt
from jwt import InvalidTokenError
from cryptography.hazmat.primitives import serialization
from app.core.config import settings

# Cache muy simple en memoria para claves resueltas por did:web
_DID_WEB_PUBKEY_CACHE: dict[str, object] = {}


def _load_private_key():
    return serialization.load_pem_private_key(
        Path(settings.priv_key_path).read_bytes(), password=None
    )


def _load_public_key_pem():
    return serialization.load_pem_public_key(
        Path(settings.pub_key_path).read_bytes()
    )


def _b64url_to_int(s: str) -> int:
    """Convierte base64url sin padding a int."""
    s += "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s.encode()), "big")


def _did_web_to_url(issuer_did: str) -> str:
    """
    did:web:example.org              -> https://example.org/.well-known/did.json
    did:web:example.org:users:alice -> https://example.org/users/alice/did.json
    """
    path = issuer_did[len("did:web:"):]
    parts = path.split(":")
    host = parts[0]
    tail = "/".join(parts[1:])
    if tail:
        return f"https://{host}/{tail}/did.json"
    return f"https://{host}/.well-known/did.json"


def _resolve_did_web_rsa_pubkey(issuer_did: str) -> object | None:
    """
    Si issuer_did es did:web:..., descarga el did.json, extrae la JWK (RSA) del assertionMethod
    y construye una clave pública compatible con PyJWT/cryptography.
    Devuelve el objeto clave pública o None si no se puede resolver.
    """
    try:
        if not issuer_did or not issuer_did.startswith("did:web:"):
            return None

        # Cache: evita descargar/parsear en cada verificación
        if issuer_did in _DID_WEB_PUBKEY_CACHE:
            return _DID_WEB_PUBKEY_CACHE[issuer_did]

        url = _did_web_to_url(issuer_did)

        with urllib.request.urlopen(url, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            doc = json.loads(raw)

        # 1) assertionMethod → id de la clave
        am = doc.get("assertionMethod", [])
        if not am:
            return None
        ref = am[0] if isinstance(am, list) else am
        if isinstance(ref, dict):  # por si viniera en objeto, usa su "id"
            ref = ref.get("id")

        # 2) verificationMethod con ese id
        vms = doc.get("verificationMethod", [])
        vm = next((x for x in vms if x.get("id") == ref), None)
        if not vm:
            return None

        jwk = vm.get("publicKeyJwk")
        if not jwk or jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
            return None

        # 3) Construir clave pública RSA a partir de n, e
        n = _b64url_to_int(jwk["n"])
        e = _b64url_to_int(jwk["e"])

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        pub_numbers = rsa.RSAPublicNumbers(e, n)
        pubkey = pub_numbers.public_key(default_backend())

        _DID_WEB_PUBKEY_CACHE[issuer_did] = pubkey
        return pubkey

    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, json.JSONDecodeError):
        # Red/timeout/formato: devuelve None para permitir fallback (si está habilitado)
        return None
    except Exception:
        # Cualquier otra excepción: también devolvemos None para no romper flujo
        return None


def sign_vc(payload: dict) -> str:
    key = _load_private_key()
    return jwt.encode(payload, key, algorithm=settings.jwt_alg)


def verify_vc(token: str) -> dict:
    """
    Verifica un VC-JWT con:
    - did:web (si USE_DID_WEB=true y el iss es did:web:...), y si falla
    - fallback a PEM local (si ALLOW_PEM_FALLBACK=true), o error si no.
    """
    try:
        # 1) Decodifica sin verificar para leer 'iss'
        unverified = jwt.decode(token, options={"verify_signature": False})
        iss = unverified.get("iss", "")

        pub = None
        # 2) did:web activado y 'iss' compatible
        if settings.use_did_web and isinstance(iss, str) and iss.startswith("did:web:"):
            pub = _resolve_did_web_rsa_pubkey(iss)

        # 3) Fallback a PEM si no hay pub de did:web o no está activado
        if pub is None:
            if settings.allow_pem_fallback:
                pub = _load_public_key_pem()
            else:
                return {"valid": False, "reason": "no-public-key-available"}

        # 4) Verificación firma + tiempos
        data = jwt.decode(token, pub, algorithms=[settings.jwt_alg])
        return {"valid": True, "payload": data}

    except InvalidTokenError as e:
        return {"valid": False, "reason": str(e)}
    except Exception as e:
        return {"valid": False, "reason": f"verify-error: {e}"}
