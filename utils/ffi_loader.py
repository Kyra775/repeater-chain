import ctypes
import os
import platform

def load_crypto_lib():
    ext = '.dll' if platform.system() == 'Windows' else '.so'
    lib_path = os.path.join(os.path.dirname(__file__), '../crypto_core/libpassword_hash' + ext)
    
    lib = ctypes.CDLL(lib_path)
    
    lib.password_to_keypair.argtypes = [
        ctypes.c_char_p,                   # password
        ctypes.POINTER(ctypes.c_ubyte * 32), # public_key
        ctypes.POINTER(ctypes.c_ubyte * 64)  # private_key
    ]
    lib.password_to_keypair.restype = None
    
    lib.verify_password.argtypes = [
        ctypes.c_char_p,                 # password
        ctypes.POINTER(ctypes.c_ubyte * 32) # stored_public_key
    ]
    lib.verify_password.restype = ctypes.c_int
    
    return lib

crypto_lib = load_crypto_lib()
