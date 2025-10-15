# app/main.py
from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.api.issuer import router as issuer_router
from app.api.verifier import router as verifier_router
from app.api.holder import router as holder_router

from app.db.session import engine
from app.db.models import Base

@asynccontextmanager
async def lifespan(app: FastAPI):
    # === STARTUP ===
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # === SHUTDOWN (opcional) ===
    await engine.dispose()

app = FastAPI(title="DAP HYROX TFG (Py3.13)", lifespan=lifespan)

app.include_router(issuer_router, prefix="/issuer", tags=["issuer"])
app.include_router(verifier_router, prefix="/verifier", tags=["verifier"])
app.include_router(holder_router,   prefix="/holder",   tags=["holder"])

@app.get("/")
def root():
    return {"ok": True}
