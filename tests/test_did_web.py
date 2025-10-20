# tests/test_did_web.py
import json
import base64

from app.core.config import settings
from app.core.crypto import _load_public_key_pem


def _b64url(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7)//8, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _fake_didjson_for_current_pem(issuer_did: str) -> dict:
    """Construye un did.json con JWK RSA que corresponde a tu PEM local."""
    pub = _load_public_key_pem()
    numbers = pub.public_numbers()
    jwk = {"kty": "RSA", "n": _b64url(numbers.n), "e": _b64url(numbers.e)}

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": issuer_did,
        "verificationMethod": [{
            "id": f"{issuer_did}#keys-1",
            "type": "JsonWebKey2020",
            "controller": issuer_did,
            "publicKeyJwk": jwk
        }],
        "assertionMethod": [f"{issuer_did}#keys-1"]
    }


def _mk_urlopen_mock(doc: dict):
    """Crea un mock de urllib.request.urlopen que devuelve doc como JSON."""
    class _Resp:
        def __init__(self, payload: bytes):
            self._payload = payload
        def read(self):
            return self._payload
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    payload = json.dumps(doc).encode("utf-8")

    def _urlopen(url, timeout=5):
        # Puedes añadir asserts si quieres validar la URL
        return _Resp(payload)

    return _urlopen


def test_did_web_success(monkeypatch, client):
    """
    Caso feliz: USE_DID_WEB=true, issuer did:web, se resuelve JWK válida y la verificación es OK.
    """
    issuer = "did:web:test.example"
    settings.use_did_web = True
    settings.allow_pem_fallback = False
    settings.issuer_did = issuer  # para que el /issuer/issue firme con este iss

    # Mock network -> responde did.json válido coherente con PEM local
    from urllib import request as _req
    monkeypatch.setattr(_req, "urlopen", _mk_urlopen_mock(_fake_didjson_for_current_pem(issuer)))

    # Emitir
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    assert r.status_code == 200
    token = r.json()["token"]

    # Verificar por token (usará did:web -> JWK)
    vr = client.post("/verifier/verify", json={"token": token})
    assert vr.status_code == 200
    out = vr.json()
    assert out["valid"] is True
    assert out["claims"]["iss"] == issuer

    # Reset flags
    settings.use_did_web = False
    settings.allow_pem_fallback = True
    settings.issuer_did = "did:example:issuerHYX"


def test_did_web_network_error_with_fallback(monkeypatch, client):
    """
    Error de red: USE_DID_WEB=true pero ALLOW_PEM_FALLBACK=true => verifica OK con PEM local.
    """
    settings.use_did_web = True
    settings.allow_pem_fallback = True
    settings.issuer_did = "did:web:test.example"

    # Mock network -> lanza error
    from urllib import request as _req
    def _boom(url, timeout=5):
        raise OSError("network down")
    monkeypatch.setattr(_req, "urlopen", _boom)

    # Emitir y verificar (debe pasar por fallback PEM)
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    token = r.json()["token"]

    vr = client.post("/verifier/verify", json={"token": token})
    assert vr.status_code == 200
    assert vr.json()["valid"] is True

    # Reset
    settings.use_did_web = False
    settings.allow_pem_fallback = True
    settings.issuer_did = "did:example:issuerHYX"


def test_did_web_network_error_without_fallback(monkeypatch, client):
    """
    Error de red: USE_DID_WEB=true y ALLOW_PEM_FALLBACK=false => valid:false (no clave disponible).
    """
    # Limpia caché did:web para evitar reutilizar una clave previa de otro test
    from app.core import crypto as c
    c._DID_WEB_PUBKEY_CACHE.clear()

    settings.use_did_web = True
    settings.allow_pem_fallback = False
    settings.issuer_did = "did:web:test.example"

    # Mock network -> lanza error
    from urllib import request as _req
    def _boom(url, timeout=5):
        raise OSError("network down")
    monkeypatch.setattr(_req, "urlopen", _boom)

    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    token = r.json()["token"]

    vr = client.post("/verifier/verify", json={"token": token})
    assert vr.status_code == 200
    out = vr.json()
    assert out["valid"] is False
    # No asserts sobre el texto exacto del motivo para no acoplarlo en exceso
    assert "reason" in out

    # Reset
    settings.use_did_web = False
    settings.allow_pem_fallback = True
    settings.issuer_did = "did:example:issuerHYX"
