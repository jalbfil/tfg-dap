# TFG-DAP · HYROX MVP (FastAPI + SQLite + JWT/RS256)

MVP de **pasaporte digital de atleta** (DAP) para eventos HYROX:
- **Issuer**: emite credenciales firmadas (JWT/RS256).
- **Holder**: lista credenciales y genera **QR** con `jti`.
- **Verifier**: verifica por **token** y por **JTI** (estado y revocación).

> ✅ Repo reproducible: los **tests** generan claves RSA efímeras y usan una **BD temporal**.  
> No necesitas `.env` ni `keys/` para ejecutar `pytest`.
>
> [![tests](https://github.com/jalbfil/tfg-dap/actions/workflows/tests.yml/badge.svg)](https://github.com/jalbfil/tfg-dap/actions/workflows/tests.yml)

---

## 1) Requisitos

- **Python 3.10+** (con `pip` y `venv`)
- Windows/PowerShell (o cualquier SO con Python 3.13)

---

## 2) Instalar y ejecutar (modo local)

```powershell
cd C:\tfg-dap-2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# (solo para ejecutar la API, no para tests)
copy .env.example .env
mkdir keys
# Copia tus claves en:
#   keys\issuer_private.pem
#   keys\issuer_public.pem

python -m uvicorn app.main:app --reload
# Swagger: http://127.0.0.1:8000/docs


