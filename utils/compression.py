import hashlib
import json
import base64
from typing import Dict, Any
from utils.hashing import poseidon_hash
from utils.crypto import encrypt_payload, sign_proof
from crypto_core.ffi_loader import generate_zk_snark_proof


class CompressionError(Exception):
    pass


def validate_metadata(metadata: Dict[str, Any]) -> None:
    required_fields = ["type", "from"]
    for field in required_fields:
        if field not in metadata or not metadata[field]:
            raise CompressionError(f"Missing required metadata field: {field}")
    # Optionally add more checks here


def serialize_metadata(metadata: Dict[str, Any]) -> str:
    try:
        return json.dumps(metadata, separators=(',', ':'), sort_keys=True)
    except Exception as e:
        raise CompressionError(f"Metadata serialization failed: {e}")


def hash_metadata(serialized: str) -> str:
    try:
        # Combine multiple hash functions for extra security
        blake2s_digest = hashlib.blake2s(serialized.encode()).hexdigest()
        poseidon_digest = poseidon_hash(serialized)
        combined_hash = hashlib.sha3_256(
            (blake2s_digest + poseidon_digest).encode()
        ).hexdigest()
        return combined_hash
    except Exception as e:
        raise CompressionError(f"Metadata hashing failed: {e}")


def compress_tx(metadata: Dict[str, Any]) -> str:
    validate_metadata(metadata)
    serialized = serialize_metadata(metadata)
    digest = hash_metadata(serialized)
    try:
        zk_proof = generate_zk_snark_proof(serialized)
    except Exception as e:
        raise CompressionError(f"ZK-SNARK proof generation failed: {e}")
    try:
        signature = sign_proof(zk_proof, metadata.get("from"))
    except Exception as e:
        raise CompressionError(f"Proof signing failed: {e}")
    try:
        encrypted_data = encrypt_payload(serialized)
    except Exception as e:
        raise CompressionError(f"Encryption failed: {e}")

    capsule = {
        "hash": digest,
        "type": metadata.get("type", "unknown"),
        "from": metadata.get("from")[:12],
        "proof": zk_proof,
        "sig": signature,
        "enc": encrypted_data
    }

    try:
        compressed_blob = json.dumps(capsule, separators=(',', ':'))
        compressed_base64 = base64.urlsafe_b64encode(compressed_blob.encode()).decode()
        return compressed_base64
    except Exception as e:
        raise CompressionError(f"Final packaging failed: {e}")
