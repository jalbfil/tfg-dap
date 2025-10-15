# app/api/issuer.py
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import time, uuid
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import sign_vc
from app.db.session import SessionLocal
from app.db.models import Credential

router = APIRouter()

class IssueInput(BaseModel):
    athleteDid: str
    name: str
    event: dict
    result: dict
    expDays: int = 365

@router.post("/issue")
async def issue_credential(body: IssueInput):
    now = int(time.time())
    exp = int((datetime.now(timezone.utc) + timedelta(days=body.expDays)).timestamp())
    jti = f"vc-hyrox-{uuid.uuid4().hex[:12]}"

    payload = {
        "iss": settings.issuer_did,
        "sub": body.athleteDid,
        "nbf": now,
        "exp": exp,
        "jti": jti,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "HyroxResultCredential"],
            "credentialSubject": {
                "athlete": {"id": body.athleteDid, "name": body.name},
                "event": body.event,
                "result": body.result,
                "issuerMetadata": {"organization": "HYROX Org ES"},
            },
        },
    }

    token = sign_vc(payload)
    async with SessionLocal() as s:
        s.add(Credential(jti=jti, jwt=token, exp=exp, status="valid"))
        await s.commit()
    return {"jti": jti, "token": token}

class RevokeInput(BaseModel):
    jti: str
    reason: str | None = None

@router.post("/revoke")
async def revoke_credential(body: RevokeInput):
    async with SessionLocal() as s:
        res = await s.execute(select(Credential).where(Credential.jti == body.jti))
        cred = res.scalar_one_or_none()
        if not cred:
            raise HTTPException(status_code=404, detail="jti not found")
        cred.status = "revoked"
        await s.commit()
    return {"ok": True, "jti": body.jti, "status": "revoked"}

@router.get("/list")
async def list_issuer():
    async with SessionLocal() as s:
        res = await s.execute(select(Credential))
        rows = res.scalars().all()
        return [
            {"jti": r.jti, "status": r.status, "exp": r.exp, "issued_at": r.issued_at.isoformat()}
            for r in rows
        ]

@router.get("/detail")
async def detail_issuer(jti: str = Query(...)):
    async with SessionLocal() as s:
        res = await s.execute(select(Credential).where(Credential.jti == jti))
        r = res.scalar_one_or_none()
        if not r:
            raise HTTPException(status_code=404, detail="jti not found")
        return {
            "jti": r.jti,
            "status": r.status,
            "exp": r.exp,
            "issued_at": r.issued_at.isoformat(),
            "jwt_len": len(r.jwt),
        }
