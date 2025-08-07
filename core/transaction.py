import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from utils import compression
from utils.crypto import sign_data, verify_signature
from utils.hashing import generate_tx_hash


@dataclass
class TransactionMetadata:
    tx_type: str
    sender: str
    receiver: str
    value: int
    nonce: int
    signature: Optional[str] = None
    input_ref: Optional[str] = None
    timestamp: float = field(default_factory=lambda: time.time())
    fee: Optional[int] = 0
    gas_limit: Optional[int] = 0
    contract_code: Optional[str] = None  # If this is a contract deployment

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        base = {
            "tx_type": self.tx_type,
            "sender": self.sender,
            "receiver": self.receiver,
            "value": self.value,
            "nonce": self.nonce,
            "input_ref": self.input_ref,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "gas_limit": self.gas_limit,
            "contract_code": self.contract_code
        }
        if include_signature:
            base["signature"] = self.signature
        return base

    def to_ordered_json(self) -> str:
        return json.dumps(self.to_dict(include_signature=False), sort_keys=True)

    def hash(self) -> str:
        return generate_tx_hash(self.to_ordered_json())

    def sign(self, private_key: str):
        self.signature = sign_data(self.hash(), private_key)

    def verify_signature(self) -> bool:
        if not self.signature:
            return False
        return verify_signature(self.hash(), self.signature, self.sender)


class Transaction:
    def __init__(self, metadata: TransactionMetadata):
        self.meta = metadata

    def to_dict(self) -> Dict[str, Any]:
        return self.meta.to_dict()

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def hash(self) -> str:
        return self.meta.hash()

    def sign(self, private_key: str):
        self.meta.sign(private_key)

    def verify(self) -> bool:
        if not self.meta.verify_signature():
            return False

        if self.meta.tx_type not in ["transfer", "contract_call", "contract_deploy"]:
            return False

        if not isinstance(self.meta.value, int) or self.meta.value < 0:
            return False

        if not self.meta.sender or not self.meta.receiver:
            return False

        if not isinstance(self.meta.nonce, int) or self.meta.nonce < 0:
            return False

        if self.meta.tx_type == "contract_deploy" and not self.meta.contract_code:
            return False

        return True

    def compress(self) -> str:
        return compression.compress_tx(self.to_dict())

    @staticmethod
    def decompress(compressed_data: str) -> 'Transaction':
        decompressed = compression.decompress_tx(compressed_data)
        meta = TransactionMetadata(
            tx_type=decompressed["tx_type"],
            sender=decompressed["sender"],
            receiver=decompressed["receiver"],
            value=decompressed["value"],
            nonce=decompressed["nonce"],
            signature=decompressed.get("signature"),
            input_ref=decompressed.get("input_ref"),
            timestamp=decompressed.get("timestamp", time.time()),
            fee=decompressed.get("fee", 0),
            gas_limit=decompressed.get("gas_limit", 0),
            contract_code=decompressed.get("contract_code")
        )
        return Transaction(meta)

    def get_sender(self) -> str:
        return self.meta.sender

    def get_receiver(self) -> str:
        return self.meta.receiver

    def get_type(self) -> str:
        return self.meta.tx_type

    def get_nonce(self) -> int:
        return self.meta.nonce

    def get_input_ref(self) -> Optional[str]:
        return self.meta.input_ref

    def get_timestamp(self) -> float:
        return self.meta.timestamp

    def get_value(self) -> int:
        return self.meta.value

    def get_signature(self) -> Optional[str]:
        return self.meta.signature

    def get_fee(self) -> int:
        return self.meta.fee or 0

    def get_gas_limit(self) -> int:
        return self.meta.gas_limit or 0

    def is_contract_call(self) -> bool:
        return self.meta.tx_type == "contract_call"

    def is_contract_deploy(self) -> bool:
        return self.meta.tx_type == "contract_deploy"

    def is_transfer(self) -> bool:
        return self.meta.tx_type == "transfer"

    def __str__(self):
        return self.to_json()

    def summarize(self) -> str:
        short_sender = self.meta.sender[:8] + "..."
        short_receiver = self.meta.receiver[:8] + "..."
        return f"{self.meta.tx_type.upper()} {self.meta.value} from {short_sender} to {short_receiver}"

    def is_valid_gas_usage(self) -> bool:
        if self.is_contract_call():
            return self.get_gas_limit() > 0
        return True

    def is_fresh(self, current_time: float, tolerance: float = 60.0) -> bool:
        return abs(current_time - self.meta.timestamp) <= tolerance

    def is_same_transaction(self, other: 'Transaction') -> bool:
        return self.hash() == other.hash()

    def conflicts_with(self, other: 'Transaction') -> bool:
        return self.meta.input_ref and self.meta.input_ref == other.meta.input_ref

    def compute_execution_cost(self) -> int:
        base = 10
        fee = self.meta.fee or 0
        gas = self.meta.gas_limit or 0
        return base + fee + (gas * 2)

    def estimated_size(self) -> int:
        return len(self.to_json().encode("utf-8"))

    def is_too_large(self, max_size: int = 2048) -> bool:
        return self.estimated_size() > max_size
