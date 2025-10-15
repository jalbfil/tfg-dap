from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from io import BytesIO
import qrcode

from app.db.session import SessionLocal
from app.db.models import Credential

from app.core.config import settings

router = APIRouter()
BASE_VERIFY_URL = settings.verify_base_url

@router.get("/qr/{jti}")
async def qr_for_jti(jti: str):
    async with SessionLocal() as s:
        dbcred = (await s.execute(select(Credential).where(Credential.jti == jti))).scalar_one_or_none()
        if not dbcred:
            raise HTTPException(status_code=404, detail="Credential not found")
    verify_url = f"{BASE_VERIFY_URL}?jti={jti}"
    img = qrcode.make(verify_url)
    buf = BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@router.get("/credentials")
async def list_credentials():
    async with SessionLocal() as s:
        res = await s.execute(select(Credential))
        rows = res.scalars().all()
        return [{"jti": r.jti, "status": r.status, "exp": r.exp, "issued_at": r.issued_at.isoformat()} for r in rows]
