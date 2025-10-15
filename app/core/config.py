from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    db_url: str = Field("sqlite+aiosqlite:///./dap.sqlite3", alias="DB_URL")
    jwt_alg: str = Field("RS256", alias="JWT_ALG")
    issuer_did: str = Field("did:example:issuerHYX", alias="ISSUER_DID")
    priv_key_path: str = Field("keys/issuer_private.pem", alias="ISSUER_PRIVATE_KEY_PATH")
    pub_key_path: str = Field("keys/issuer_public.pem", alias="ISSUER_PUBLIC_KEY_PATH")
    verify_base_url: str = Field("http://127.0.0.1:8000/verifier/scan", alias="VERIFY_BASE_URL")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,   # permite usar defaults si no hay env
    )

settings = Settings()