from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # Base de datos
    db_url: str = Field("sqlite+aiosqlite:///./dap.sqlite3", alias="DB_URL")

    # Cripto/JWT
    jwt_alg: str = Field("RS256", alias="JWT_ALG")
    issuer_did: str = Field("did:example:issuerHYX", alias="ISSUER_DID")

    # Rutas de claves PEM (fallback local)
    priv_key_path: str = Field("keys/issuer_private.pem", alias="ISSUER_PRIVATE_KEY_PATH")
    pub_key_path: str = Field("keys/issuer_public.pem", alias="ISSUER_PUBLIC_KEY_PATH")

    # Verificación por JTI (para QR)
    verify_base_url: str = Field("http://127.0.0.1:8000/verifier/scan", alias="VERIFY_BASE_URL")

    # === did:web (opcional) ===
    use_did_web: bool = Field(False, alias="USE_DID_WEB")
    allow_pem_fallback: bool = Field(True, alias="ALLOW_PEM_FALLBACK")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,  # permite defaults si no hay variable de entorno
    )


settings = Settings()
