from utils import compression
import ctypes

class Transaction:
    def __init__(self, tx_type, sender, receiver, value, nonce, signature=None):
        self.tx_type = tx_type
        self.sender = sender  # 32-byte public key
        self.receiver = receiver  # 32-byte public key
        self.value = value
        self.nonce = nonce
        self.signature = signature
    
    def to_compressed(self):
        """Kompresi menjadi string 80-byte"""
        return compression.compress_tx({
            't': self.tx_type,
            's': self.sender,
            'r': self.receiver,
            'v': self.value,
            'n': self.nonce,
            'sig': self.signature
        })
    
    @classmethod
    def from_compressed(cls, compressed_str):
        data = compression.decompress_tx(compressed_str)
        return cls(
            data['t'],
            data['s'],
            data['r'],
            data['v'],
            data['n'],
            data['sig']
        )
    
    def sign(self, private_key):
        pass
