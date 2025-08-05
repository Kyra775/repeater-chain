import os
import json
from utils.ffi_loader import crypto_lib

class Wallet:
    def __init__(self, password):
        self.public_key = (ctypes.c_ubyte * 32)()
        self.private_key = (ctypes.c_ubyte * 64)()
        crypto_lib.password_to_keypair(
            password.encode('utf-8'),
            ctypes.byref(self.public_key),
            ctypes.byref(self.private_key)
        )
    
    def get_address(self):
        return bytes(self.public_key).hex()
    
    def save_to_file(self, filename):
        data = {
            'public_key': bytes(self.public_key).hex(),
            'encrypted_private': self._encrypt_private()  
        }
        with open(filename, 'w') as f:
            json.dump(data, f)
    
    @classmethod
    def login(cls, password, filename):
        with open(filename) as f:
            data = json.load(f)
        public_key = bytes.fromhex(data['public_key'])
        
        pub_arr = (ctypes.c_ubyte * 32).from_buffer_copy(public_key)
        verified = crypto_lib.verify_password(
            password.encode('utf-8'),
            ctypes.byref(pub_arr)
        )
        
        if verified:
            return cls(password)
        raise Exception("Invalid password")
