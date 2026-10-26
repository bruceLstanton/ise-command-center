from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet():
    key = current_app.config.get("ISE_PORTAL_MASTER_KEY")
    if not key:
        raise RuntimeError("ISE_PORTAL_MASTER_KEY must be configured before storing credentials")
    return Fernet(key.encode())


def encrypt_secret(value):
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value):
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Stored credential cannot be decrypted with the configured key") from exc

