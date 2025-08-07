import time
import hashlib
import uuid
from core.config import Config
from utils.hashing import merkle_root
from utils.crypto import verify_signature
from core.state import Ledger

class DAGBlock:
    def __init__(self, parent_ids, tx_list, creator_id, signature, timestamp=None):
        self.id = str(uuid.uuid4())
        self.parents = parent_ids
        self.tx_list = tx_list
        self.creator = creator_id
        self.timestamp = timestamp or time.time()
        self.signature = signature
        self.merkle = merkle_root([tx.hash() for tx in tx_list])
        self.block_hash = self._compute_hash()

    def _compute_hash(self):
        data = f"{self.id}{self.parents}{self.merkle}{self.creator}{self.timestamp}".encode()
        return hashlib.sha3_256(data).hexdigest()

    def to_dict(self):
        return {
            "id": self.id,
            "parents": self.parents,
            "txs": [tx.to_dict() for tx in self.tx_list],
            "creator": self.creator,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "merkle": self.merkle,
            "hash": self.block_hash
        }

class HashgraphDAG:
    def __init__(self):
        self.blocks = {}            
        self.active_tips = set()    
        self.child_map = {}         
        self.config = Config()
        self.max_active_blocks = self.config.max_active_blocks
        self.ledger = Ledger()

    def add_block(self, block: DAGBlock, ai_score: float) -> bool:
        if ai_score < self.config.AI_THRESHOLD:
            return False

        if block.block_hash in self.blocks:
            return False

        if not verify_signature(block.block_hash, block.signature, block.creator):
            return False

        if not self._check_parents(block.parents):
            return False

        if self._detect_double_spending(block):
            return False

        self.blocks[block.block_hash] = block
        for parent_id in block.parents:
            self.child_map.setdefault(parent_id, set()).add(block.block_hash)

        self.active_tips.add(block.block_hash)
        self._prune_tips()
        self.ledger.apply_block(block)
        return True

    def _check_parents(self, parent_ids):
        return all(pid in self.blocks for pid in parent_ids)

    def _detect_double_spending(self, block):
        seen_inputs = set()
        for tx in block.tx_list:
            if tx.input_ref in seen_inputs or self.ledger.is_spent(tx.input_ref):
                return True
            seen_inputs.add(tx.input_ref)
        return False

    def _prune_tips(self):
        if len(self.active_tips) <= self.max_active_blocks:
            return
        sorted_tips = sorted(
            self.active_tips,
            key=lambda h: self.blocks[h].timestamp
        )
        while len(sorted_tips) > self.max_active_blocks:
            old = sorted_tips.pop(0)
            self.active_tips.remove(old)

    def get_tip_blocks(self):
        return [self.blocks[bid] for bid in self.active_tips]

    def get_block(self, block_hash):
        return self.blocks.get(block_hash)

    def serialize_block(self, block: DAGBlock):
        return block.to_dict()

    def deserialize_block(self, data: dict):
        txs = [self.ledger.rebuild_transaction(tx) for tx in data["txs"]]
        return DAGBlock(
            parent_ids=data["parents"],
            tx_list=txs,
            creator_id=data["creator"],
            signature=data["signature"],
            timestamp=data["timestamp"]
        )
