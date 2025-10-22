# TFG-DAP · HYROX MVP (FastAPI + SQLite + JWT/RS256)

MVP de **pasaporte digital de atleta (DAP)** para eventos HYROX:
- **Issuer**: emite credenciales firmadas (VC-JWT/RS256).
- **Holder**: lista credenciales y genera **QR** con `jti`.
- **Verifier**: verifica por **token** y por **JTI** (incluye estado y revocación).

> ✅ Repo reproducible: los **tests** generan claves RSA efímeras y usan una **BD temporal**.  
> No necesitas `.env` ni `keys/` para ejecutar `pytest`.

---

## 1) Requisitos

- **Python 3.10+** (probado en 3.10 y 3.13)
- `pip` y `venv` instalados

---

## 2) Instalar y ejecutar (modo local)

```powershell
# 1) Clona el repo y crea entorno
cd C:\tfg-dap
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2) (Solo para ejecutar la API; NO necesario para tests)
copy .env.example .env

# 3) Claves (NO se versionan)
mkdir keys
# Copia tus claves en:
#   keys\issuer_private.pem
#   keys\issuer_public.pem

# 4) Lanza la API
python -m uvicorn app.main:app --reload
# Swagger: http://127.0.0.1:8000/docs

# DID document
DID del emisor: `did:web:jalbfil.github.io`  
DID Document: https://jalbfil.github.io/.well-known/did.json
![tests](https://github.com/jalbfil/tfg-dap/actions/workflows/ci.yml/badge.svg)

