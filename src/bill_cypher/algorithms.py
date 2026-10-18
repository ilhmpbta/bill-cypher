from Crypto.Cipher import AES, ARC4, DES

SUPPORTED_ALGORITHMS = {"AES", "DES", "RC4"}

BLOCK_SIZES = {
    "AES": AES.block_size,
    "DES": DES.block_size,
}

KEY_SIZES = {
    "AES": 32,  # AES-256
    "DES": 8,  # DES uses a 56-bit effective key
    "RC4": 32,  # 32-byte RC4 key
}


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    # Pad data for a block cipher.
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    # Remove and validate PKCS#7 padding.
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")

    padding_length = data[-1]

    if not 1 <= padding_length <= block_size:
        raise ValueError("Invalid PKCS#7 padding.")

    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding.")

    return data[:-padding_length]


def encrypt_data(
    data: bytes,
    key: bytes,
    algorithm: str,
    iv: bytes | None = None,
) -> tuple[bytes, bytes | None]:

    # Encrypt bytes and return (ciphertext, IV).
    # AES and DES use CBC mode and require an IV.
    # RC4 is a stream cipher and does not use an IV here.
    algorithm = algorithm.upper()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if len(key) != KEY_SIZES[algorithm]:
        raise ValueError(f"Invalid key length for {algorithm}.")

    if algorithm in BLOCK_SIZES:
        block_size = BLOCK_SIZES[algorithm]

        if iv is None or len(iv) != block_size:
            raise ValueError(f"{algorithm}-CBC requires a {block_size}-byte IV.")

        cipher = (
            AES.new(key, AES.MODE_CBC, iv=iv)
            if algorithm == "AES"
            else DES.new(key, DES.MODE_CBC, iv=iv)
        )

        ciphertext = cipher.encrypt(pkcs7_pad(data, block_size))
        return ciphertext, iv

    if iv is not None:
        raise ValueError("RC4 does not use an IV in this implementation.")

    return ARC4.new(key).encrypt(data), None


def decrypt_data(
    ciphertext: bytes,
    key: bytes,
    algorithm: str,
    iv: bytes | None = None,
) -> bytes:
    # Decrypt bytes previously encrypted by encrypt_data().
    algorithm = algorithm.upper()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if len(key) != KEY_SIZES[algorithm]:
        raise ValueError(f"Invalid key length for {algorithm}.")

    if algorithm in BLOCK_SIZES:
        block_size = BLOCK_SIZES[algorithm]

        if iv is None or len(iv) != block_size:
            raise ValueError(f"{algorithm}-CBC requires a {block_size}-byte IV.")

        if not ciphertext or len(ciphertext) % block_size != 0:
            raise ValueError("Invalid CBC ciphertext length.")

        cipher = (
            AES.new(key, AES.MODE_CBC, iv=iv)
            if algorithm == "AES"
            else DES.new(key, DES.MODE_CBC, iv=iv)
        )

        plaintext = cipher.decrypt(ciphertext)
        return pkcs7_unpad(plaintext, block_size)

    if iv is not None:
        raise ValueError("RC4 does not use an IV in this implementation.")

    return ARC4.new(key).decrypt(ciphertext)
