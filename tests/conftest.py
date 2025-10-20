# tests/conftest.py
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# --- Asegurar que podemos importar 'app' desde la raíz del repo ---
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- Generación de claves efímeras (RSA 2048) ---
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _generate_ephemeral_keys(keys_dir: Path) -> tuple[Path, Path]:
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (keys_dir / "issuer_private.pem").write_bytes(pem_priv)

    pem_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (keys_dir / "issuer_public.pem").write_bytes(pem_pub)

    return (keys_dir / "issuer_private.pem"), (keys_dir / "issuer_public.pem")


def _prepare_test_env() -> None:
    tmp = (ROOT / ".pytest_tmp").absolute()
    tmp.mkdir(exist_ok=True)

    # BD SQLite temporal para pruebas
    db_path = (tmp / "test.sqlite3").as_posix()
    os.environ["DB_URL"] = f"sqlite+aiosqlite:///{db_path}"

    # Variables mínimas para que Settings funcione sin .env
    os.environ["JWT_ALG"] = "RS256"
    os.environ["ISSUER_DID"] = "did:example:issuerHYX"
    os.environ["VERIFY_BASE_URL"] = "http://127.0.0.1:8000/verifier/scan"

    # Claves efímeras (ruta por ENV, consistente con tus Settings alias)
    priv_path, pub_path = _generate_ephemeral_keys(tmp)
    os.environ["ISSUER_PRIVATE_KEY_PATH"] = priv_path.as_posix()
    os.environ["ISSUER_PUBLIC_KEY_PATH"]  = pub_path.as_posix()


@pytest.fixture(scope="session")
def client():
    """
    Cliente de pruebas con entorno efímero:
    - BD sqlite en .pytest_tmp/test.sqlite3
    - Claves RSA generadas al vuelo en .pytest_tmp/
    - ENV configurado sin depender de .env ni keys/
    """
    _prepare_test_env()
    from app.main import app
    # Con 'with' forzamos lifespan: crea tablas en startup y cierra engine en shutdown
    with TestClient(app) as c:
        yield c


# --- Reset de settings después de cada test (autouse) ---
@pytest.fixture(autouse=True)
def _reset_settings_between_tests():
    from app.core.config import settings
    snapshot = (settings.use_did_web, settings.allow_pem_fallback, settings.issuer_did)
    yield
    settings.use_did_web, settings.allow_pem_fallback, settings.issuer_did = snapshot
