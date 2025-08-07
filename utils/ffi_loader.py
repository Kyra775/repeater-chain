import ctypes
import os
import platform
from ctypes import c_char_p, c_size_t, POINTER, c_ubyte, c_int

def load_crypto_lib():
    ext = '.dll' if platform.system() == 'Windows' else '.so'
    lib_path = os.path.join(os.path.dirname(__file__), '../crypto_core/libpassword_hash' + ext)

    if not os.path.exists(lib_path):
        raise FileNotFoundError(f"Crypto library not found at: {lib_path}")

    try:
        lib = ctypes.CDLL(lib_path)
    except OSError as e:
        raise RuntimeError(f"Failed to load crypto library: {e}")

    # void password_to_keypair(const char *password, unsigned char *public_key,
    #                          unsigned char *private_key, unsigned char *salt,
    #                          unsigned char *hmac, size_t *out_len)
    lib.password_to_keypair.argtypes = [
        c_char_p,  # password
        POINTER(c_ubyte * 32),  # public_key
        POINTER(c_ubyte * 64),  # private_key
        POINTER(c_ubyte * 16),  # salt
        POINTER(c_ubyte * 16),  # hmac
        POINTER(c_size_t)       # output_len
    ]
    lib.password_to_keypair.restype = None

    # int verify_password(const char *password,
    #                     const unsigned char *stored_data,
    #                     size_t data_len)
    lib.verify_password.argtypes = [
        c_char_p,
        POINTER(c_ubyte),
        c_size_t
    ]
    lib.verify_password.restype = c_int

    return lib

crypto_lib = load_crypto_lib()
