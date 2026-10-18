import base64
import json
import secrets
from typing import Any

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from .algorithms import (
    BLOCK_SIZES,
    KEY_SIZES,
    SUPPORTED_ALGORITHMS,
    decrypt_data,
    encrypt_data,
)

VERSION = 1
SALT_SIZE = 16
PBKDF2_ROUNDS = 600_000


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Expected a Base64 string.")

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Invalid Base64 data.") from exc


def _derive_key(password: str, salt: bytes, algorithm: str) -> bytes:
    # Derive an algorithm-sized key from a password and salt.
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")

    return PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZES[algorithm],
        count=PBKDF2_ROUNDS,
        hmac_hash_module=SHA256,
    )


def encryptbytes(
    data: bytes,
    password: str,
    algorithm: str = "AES",
    name: str = "data",
) -> bytes:
    # Encrypt bytes and return a UTF-8 JSON envelope as bytes.
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes.")

    if not isinstance(name, str):
        raise TypeError("name must be a string.")

    algorithm = algorithm.upper()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Choose from {', '.join(sorted(SUPPORTED_ALGORITHMS))}."
        )

    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt, algorithm)

    iv = (
        secrets.token_bytes(BLOCK_SIZES[algorithm])
        if algorithm in BLOCK_SIZES
        else None
    )

    ciphertext, iv = encrypt_data(data, key, algorithm, iv)

    envelope: dict[str, Any] = {
        "version": VERSION,
        "algorithm": algorithm,
        "name": name,
        "salt": _b64encode(salt),
        "ciphertext": _b64encode(ciphertext),
    }

    if iv is not None:
        envelope["iv"] = _b64encode(iv)

    return json.dumps(
        envelope,
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")


def decryptbytes(
    envelope: str | bytes,
    password: str,
) -> tuple[bytes, str]:
    # Decrypt an envelope and return (plaintext, original_name).
    try:
        if isinstance(envelope, bytes):
            envelope = envelope.decode("utf-8")

        fields = json.loads(envelope)

        if not isinstance(fields, dict):
            raise TypeError("Envelope must be a JSON object.")

        if fields.get("version") != VERSION:
            raise ValueError("Unsupported envelope version.")

        algorithm = fields["algorithm"]

        if not isinstance(algorithm, str):
            raise TypeError("Invalid algorithm field.")

        algorithm = algorithm.upper()

        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        salt = _b64decode(fields["salt"])
        ciphertext = _b64decode(fields["ciphertext"])

        if len(salt) != SALT_SIZE:
            raise ValueError("Invalid salt length.")

        if algorithm in BLOCK_SIZES:
            iv = _b64decode(fields["iv"])
            if len(iv) != BLOCK_SIZES[algorithm]:
                raise ValueError("Invalid IV length.")
        else:
            if "iv" in fields:
                raise ValueError("RC4 envelope must not contain an IV.")
            iv = None

        name = fields.get("name", "data")

        if not isinstance(name, str):
            raise TypeError("Invalid name field.")

    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid encrypted envelope.") from exc

    key = _derive_key(password, salt, algorithm)

    try:
        plaintext = decrypt_data(ciphertext, key, algorithm, iv)
    except ValueError as exc:
        raise ValueError(
            "Decryption failed: wrong password, corrupted data, or invalid padding."
        ) from exc

    return plaintext, name
