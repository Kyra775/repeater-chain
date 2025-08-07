import os
import json
import base64
import ctypes
import secrets
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from utils.ffi_loader import crypto_lib

class WalletSecurityException(Exception):
    pass

class Wallet:
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.public_key = (ctypes.c_ubyte * 32)()
        self.private_key = (ctypes.c_ubyte * 64)()
        
        crypto_lib.password_to_keypair(
            self.password,
            ctypes.byref(self.public_key),
            ctypes.byref(self.private_key)
        )

    def get_address(self) -> str:
        return hashlib.sha256(bytes(self.public_key)).hexdigest()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=32,
            salt=salt,
            iterations=150_000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def _encrypt_private_key(self) -> dict:
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        key = self._derive_key(salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(bytes(self.private_key)) + encryptor.finalize()

        return {
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'data': base64.b64encode(encrypted).decode()
        }

    def save_to_file(self, filename: str):
        data = {
            'public_key': base64.b64encode(bytes(self.public_key)).decode(),
            'encrypted_private_key': self._encrypt_private_key()
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    @classmethod
    def login(cls, password: str, filename: str):
        with open(filename, 'r') as f:
            data = json.load(f)

        encrypted_data = data['encrypted_private_key']
        salt = base64.b64decode(encrypted_data['salt'])
        iv = base64.b64decode(encrypted_data['iv'])
        encrypted = base64.b64decode(encrypted_data['data'])

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashlib.sha256(),
                length=32,
                salt=salt,
                iterations=150_000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            private_key_bytes = decryptor.update(encrypted) + decryptor.finalize()

            # Rebuild wallet
            wallet = cls(password)
            ctypes.memmove(wallet.private_key, private_key_bytes, 64)
            return wallet

        except (InvalidKey, Exception):
            raise WalletSecurityException("Invalid password or corrupted wallet file")
