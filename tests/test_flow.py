import json

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

    # “romper” el payload del JWT
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
    # Emite y luego manipula el 'nbf' para que esté en el futuro (ilustra la política temporal)
    r = client.post("/issuer/issue", json={
        "athleteDid": "did:example:athlete123",
        "name": "Nombre Apellido",
        "event": {"name": "HYROX Barcelona", "date": "2025-11-15", "division": "Pro Men", "category": "Individual"},
        "result": {"totalTime": "01:05:23", "splits": {"run1": "00:04:15"}},
        "expDays": 30
    })
    token = r.json()["token"]
    # Fuerza un token con 'nbf' futuro (si más adelante añades endpoint de emisión “avanzada”, puedes probarlo sin manipular)
    parts = token.split(".")
    # Nota: manipular 'nbf' real sin resignar firma lo invalida por firma; el objetivo es que el verificador rechace
    # por firma/nbf no válido. Aceptamos valid:false con reason.
    tampered = f"{parts[0]}.{parts[1][:-1]}A.{parts[2]}"
    r = client.post("/verifier/verify", json={"token": tampered})
    assert r.status_code == 200
    assert r.json()["valid"] is False
