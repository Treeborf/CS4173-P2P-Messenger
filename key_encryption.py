def encrypt_message(plaintext: str, password: bytes, aes_mode=True) -> str:
    import base64, os, json
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from Crypto.Cipher import DES
    from Crypto.Protocol.KDF import PBKDF2 as PBKDF2_DES
    from Crypto.Util.Padding import pad as des_pad

    if aes_mode:
        salt = os.urandom(16)
        iv = os.urandom(16)
        kdf = PBKDF2HMAC(hashes.SHA256(), 16, salt, 100_000, backend=default_backend())
        key = kdf.derive(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        mode_label = "AES"
    else:
        salt = os.urandom(8)
        iv = os.urandom(8)
        key = PBKDF2_DES(password, salt, dkLen=8, count=100_000)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded = des_pad(plaintext.encode(), 8, style='pkcs7')
        ciphertext = cipher.encrypt(padded)
        mode_label = "DES"

    return json.dumps({
        'mode': mode_label,
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    })


def decrypt_message(json_str: str, password: bytes, aes_mode=True) -> str:
    import base64, json
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from Crypto.Cipher import DES
    from Crypto.Protocol.KDF import PBKDF2 as PBKDF2_DES
    from Crypto.Util.Padding import unpad as des_unpad

    obj = json.loads(json_str)
    salt = base64.b64decode(obj['salt'])
    iv = base64.b64decode(obj['iv'])
    ciphertext = base64.b64decode(obj['ciphertext'])
    mode_sent = obj.get("mode")

    try:
        # Check mode mismatch
        if (aes_mode and mode_sent != "AES") or (not aes_mode and mode_sent != "DES"):
            return "__MODE_MISMATCH__"

        if aes_mode:
            kdf = PBKDF2HMAC(hashes.SHA256(), 16, salt, 100_000, backend=default_backend())
            key = kdf.derive(password)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        else:
            key = PBKDF2_DES(password, salt, dkLen=8, count=100_000)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            plaintext = des_unpad(padded, 8, style='pkcs7')

        return plaintext.decode()

    except Exception:
        return None
