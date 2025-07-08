# key_encryption.py
import base64, os, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2 as PBKDF2_DES
from Crypto.Util.Padding import pad as des_pad
from Crypto.Util.Padding import unpad as des_unpad

# Encrypts a message with either AES-128 or DES-56 encryption
# Takes in a plaintext string, a password in bytes to derive the key from, and a bool function to swap between AES (true) and DES (false)
# AES is the default encryption method
def encrypt_message(plaintext: str, password: bytes, aes_mode=True) -> str:
    
    if aes_mode:
        # AES-128 Encryption from Cryptography
        salt = os.urandom(16) # Creates a randomized 16-bit salt
        iv = os.urandom(16) # Creates a randomized 16-bit initialization vector

        # Create key derivation function using PBKDF2 with SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,          # 16 bytes = 128 bits for AES key
            salt=salt,
            iterations=100_000, # High iteration count for security
            backend=default_backend()
        )
        key = kdf.derive(password)  # Derive encryption key from password

        # Create AES cipher in CBC mode (Cipher Block Chaining)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the plaintext to AES block size (128 bits = 16 bytes)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()

        # Encrypt the padded plaintext and set the mode_label to AES
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        mode_label = "AES"
    else:
        # DES Solution
        salt = os.urandom(8) # 8-bit random salt
        iv = os.urandom(8) # 8-bit random initialization vector

        # Derive key using PBKDF2, but in DES mode
        key = PBKDF2_DES(password, salt, dkLen=8, count=100_000)

        # Create a DES key in CBC mode 
        cipher = DES.new(key, DES.MODE_CBC, iv)

        # Pad the plaintext to a DES block size (64 bits = 8 bytes)
        padded = des_pad(plaintext.encode(), 8, style='pkcs7')

        # Encrypt the padded plaintext and set the mode to DES
        ciphertext = cipher.encrypt(padded)
        mode_label = "DES"

    # Once we encrypt using either AES or DES, we return a JSON dump that contains the ciphertext, IV, salt, and mode for decryption later
    return json.dumps({
        'mode': mode_label,
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    })

# Decrypts a message that was encrypted using encrypt_message
# Takes in a json_str containing the information in the JSON dump from encrypt_message, the password in bytes, and whether it is AES or DES
# Returns the decrypted plaintext, or an error message
def decrypt_message(json_str: str, password: bytes, aes_mode=True) -> str:

    # Read the JSON dump to get the information to decrypt
    obj = json.loads(json_str) # load the object
    salt = base64.b64decode(obj['salt']) # find the salt value
    iv = base64.b64decode(obj['iv']) # find the iv value
    ciphertext = base64.b64decode(obj['ciphertext']) # find the ciphertext
    mode_sent = obj.get("mode") # determine the mode

    try:
        # Check mode mismatch
        if (aes_mode and mode_sent != "AES") or (not aes_mode and mode_sent != "DES"):
            return "__MODE_MISMATCH__"

        if aes_mode:
            # AES Mode
            # Recreate the key derivation
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=16,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            key = kdf.derive(password)  # Derive same key used for encryption

            # Create the AES cipher in CBC mode
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt the ciphertext
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the decrypted plaintext so we can output the actual plaintext
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        else:
            # DES Mode
            # Recreate the key
            key = PBKDF2_DES(password, salt, dkLen=8, count=100_000)

            # Create the DES Cipher
            cipher = DES.new(key, DES.MODE_CBC, iv)
            
            # Decrypt the ciphertext and unpad it
            padded = cipher.decrypt(ciphertext)
            plaintext = des_unpad(padded, 8, style='pkcs7')

        return plaintext.decode() # Returns the decrypted plaintext with no padding
 
    except Exception:
        # Return None if we have any decryption errors like wrong password or corrupted data
        return None
    

