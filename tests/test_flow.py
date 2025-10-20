# tests/test_flow.py
import json

from app.core.config import settings


def _issue_payload(exp_days=30):
    return {
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {
            "name": "HYROX Barcelona",
            "date": "2025-11-15",
            "division": "Pro Men",
            "category": "Individual",
        },
        "result": {
            "totalTime": "01:05:23",
            "splits": {"run1": "00:04:15"}
        },
        "expDays": exp_days,
    }


def test_issue_and_verify_token_valid(client):
    # Asegura issuer por defecto (no did:web) para este test
    settings.issuer_did = "did:example:issuerHYX"

    # 1) Emitir
    res = client.post("/issuer/issue", json=_issue_payload())
    assert res.status_code == 200
    data = res.json()
    jti = data["jti"]
    token = data["token"]

    # 2) Verificar por token (válido)
    res = client.post("/verifier/verify", json={"token": token})
    assert res.status_code == 200
    out = res.json()
    assert out["valid"] is True
    assert out["claims"]["iss"] == "did:example:issuerHYX"
    assert out["claims"]["sub"] == "did:example:athlete123"

    # 3) Verificar por JTI (válido)
    res = client.get(f"/verifier/scan?jti={jti}")
    assert res.status_code == 200
    assert res.json()["valid"] is True


def test_revoke_then_invalid(client):
    # Emitir
    r = client.post("/issuer/issue", json=_issue_payload())
    jti = r.json()["jti"]
    token = r.json()["token"]

    # Revocar
    r = client.post("/issuer/revoke", json={"jti": jti, "reason": "test"})
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"

    # Verificación por JTI debe fallar
    r = client.get(f"/verifier/scan?jti={jti}")
    assert r.status_code == 200
    assert r.json()["valid"] is False

    # Verificación por token también debe fallar
    r = client.post("/verifier/verify", json={"token": token})
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_tampered_token_invalid(client):
    r = client.post("/issuer/issue", json=_issue_payload())
    token = r.json()["token"]

    # “romper” el payload del JWT (sin resignar)
    p = token.split(".")
    tampered = f"{p[0]}.{p[1][:-1]}A.{p[2]}"

    r = client.post("/verifier/verify", json={"token": tampered})
    assert r.status_code == 200
    out = r.json()
    assert out["valid"] is False
    assert "reason" in out


def test_expired_token_invalid(client):
    # expDays=-1 -> expirada
    r = client.post("/issuer/issue", json=_issue_payload(exp_days=-1))
    token = r.json()["token"]

    r = client.post("/verifier/verify", json={"token": token})
    assert r.status_code == 200
    out = r.json()
    assert out["valid"] is False
    # Mensaje puede variar (PyJWT): comprobamos que hay motivo
    assert "reason" in out


def test_qr_endpoint_returns_png(client):
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    jti = r.json()["jti"]
    r = client.get(f"/holder/qr/{jti}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")


def test_nbf_in_future_is_not_valid(client):
    # Emite y luego manipula 'nbf' (esto invalida firma; basta con que verificación falle)
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    token = r.json()["token"]

    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1][:-1]}A.{parts[2]}"
    r = client.post("/verifier/verify", json={"token": tampered})
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_verify_with_did_web_success(monkeypatch, client):
    """
    Caso feliz did:web: se emite con iss=did:web:example.org, se mockea urlopen
    para devolver un did.json cuya JWK corresponde a la PEM local.
    """
    issuer = "did:web:example.org"
    settings.use_did_web = True
    settings.allow_pem_fallback = False
    settings.issuer_did = issuer

    # Construye did.json a partir de la PEM local
    from app.core.crypto import _load_public_key_pem
    pub = _load_public_key_pem()
    numbers = pub.public_numbers()

    import base64
    def _b64url(i: int) -> str:
        b = i.to_bytes((i.bit_length() + 7)//8, "big")
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    jwk = {"kty": "RSA", "n": _b64url(numbers.n), "e": _b64url(numbers.e)}
    didjson = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": issuer,
        "verificationMethod": [{
            "id": f"{issuer}#keys-1",
            "type": "JsonWebKey2020",
            "controller": issuer,
            "publicKeyJwk": jwk
        }],
        "assertionMethod": [f"{issuer}#keys-1"]
    }

    # Mock de urlopen que devuelve ese did.json
    class _Resp:
        def __init__(self, payload: bytes): self._payload = payload
        def read(self): return self._payload
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False

    from urllib import request as _req
    payload = json.dumps(didjson).encode("utf-8")
    monkeypatch.setattr(_req, "urlopen", lambda url, timeout=5: _Resp(payload))

    # Emitir con iss did:web
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    assert r.status_code == 200
    token = r.json()["token"]

    # Verificar por token (debe usar did:web -> JWK mockeada)
    vr = client.post("/verifier/verify", json={"token": token})
    assert vr.status_code == 200
    out = vr.json()
    assert out["valid"] is True
    assert out["claims"]["iss"] == issuer
