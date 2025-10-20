from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.core.crypto import verify_vc
from app.db.session import SessionLocal
from app.db.models import Credential

router = APIRouter()


class VerifyInput(BaseModel):
    token: str


@router.post("/verify")
async def verify_token(body: VerifyInput):
    # verify_vc ya intenta did:web si está activado y hace fallback a PEM si procede
    res = verify_vc(body.token)
    if not res["valid"]:
        return {"valid": False, "reason": res.get("reason", "invalid")}

    payload = res["payload"]
    jti = payload.get("jti")

    # Si el token no trae jti, o el jti no está en la BD, NO lo damos por válido
    if not jti:
        return {"valid": False, "reason": "no-jti-in-token"}

    async with SessionLocal() as s:
        dbcred = (await s.execute(select(Credential).where(Credential.jti == jti))).scalar_one_or_none()
        if not dbcred:
            return {"valid": False, "reason": "jti-not-found"}
        if dbcred.status != "valid":
            return {"valid": False, "reason": f"status={dbcred.status}"}

    return {
        "valid": True,
        "claims": {
            "jti": jti,
            "iss": payload.get("iss"),
            "sub": payload.get("sub"),
            "exp": payload.get("exp"),
        },
    }


@router.get("/scan")
async def scan_by_jti(jti: str = Query(...)):
    async with SessionLocal() as s:
        dbcred = (await s.execute(select(Credential).where(Credential.jti == jti))).scalar_one_or_none()
        if not dbcred:
            return {"valid": False, "reason": "jti not found"}
        token = dbcred.jwt

    res = verify_vc(token)
    if not res["valid"]:
        return {"valid": False, "reason": res.get("reason", "invalid")}
    if dbcred.status != "valid":
        return {"valid": False, "reason": f"status={dbcred.status}"}

    payload = res["payload"]
    return {
        "valid": True,
        "claims": {
            "jti": jti,
            "iss": payload.get("iss"),
            "sub": payload.get("sub"),
            "exp": payload.get("exp"),
        },
    }
