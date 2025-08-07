import asyncio
import json
import uuid
import time
import hashlib
import secrets
from typing import Dict, List, Tuple, Set, Optional
from network.encrypted_connection import EncryptedConnection
from core.merkle_tree import MerkleTree
from core.transaction import Transaction, TransactionType
from core.dag import DAG, Block
from core.state import Ledger, AccountState
from core.wallet import Wallet, KeyPair
from core.config import Config
from validator_ai.engine import ValidatorEngine
from utils.logger import log
from utils.crypto import sign_data, verify_signature
from utils.pki import PKI
from utils.ratelimiter import RateLimiter
from utils.tor_proxy import TorProxy

class Node:
    def __init__(self, host: str, port: int, tor_port: int = 9050):
        self.id = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        self.host = host
        self.port = port
        self.peers_lock = asyncio.Lock()
        self.peers: Set[Tuple[str, int]] = set()
        self.connection_pool: Dict[str, EncryptedConnection] = {}
        self.dag = DAG()
        self.ledger = Ledger()
        self.wallet = Wallet()
        self.config = Config.load()
        self.validator_engine = ValidatorEngine(self)
        self.rate_limiter = RateLimiter(max_requests=100, interval=60)
        self.pki = PKI()
        self.tor_proxy = TorProxy(tor_port)
        self.heartbeat_task = None
        self.sync_task = None
        self.last_block_hash = None
        self.pending_transactions = asyncio.Queue()
        self.consensus_lock = asyncio.Lock()
        self.blacklist: Set[str] = set()

    async def start(self):
        """Start node services"""
        await self._load_genesis_block()
        asyncio.create_task(self._process_transactions())
        asyncio.create_task(self._consensus_loop())
        self.heartbeat_task = asyncio.create_task(self._heartbeat())
        self.sync_task = asyncio.create_task(self._sync_blocks())
        await self.server.start(self.host, self.port)

    async def _load_genesis_block(self):
        """Load or create genesis block"""
        if not self.dag.blocks:
            genesis_block = self._create_genesis_block()
            self.dag.add_block(genesis_block)
            self.last_block_hash = genesis_block.hash

    def _create_genesis_block(self) -> Block:
        """Create genesis block with initial distribution"""
        genesis_tx = Transaction(
            tx_type=TransactionType.GENESIS,
            sender="0",
            receiver=self.wallet.address,
            amount=1000000,
            fee=0,
            nonce=0,
            timestamp=int(time.time()),
            signature="",
            data="Genesis Allocation"
        )
        genesis_tx.sign(self.wallet.private_key)
        return Block(
            index=0,
            transactions=[genesis_tx],
            previous_hash="0" * 64,
            timestamp=int(time.time()),
            validator=self.wallet.address,
            signature=""
        )

    async def _process_transactions(self):
        """Background task to process pending transactions"""
        while True:
            tx = await self.pending_transactions.get()
            try:
                if self.validator_engine.validate_transaction(tx):
                    async with self.consensus_lock:
                        self.dag.add_transaction(tx)
                        self.ledger.apply_transaction(tx)
                        await self._broadcast({
                            "type": "transaction",
                            "data": tx.to_dict(),
                            "node_id": self.id,
                            "timestamp": int(time.time())
                        })
            except Exception as e:
                log(f"Transaction processing failed: {e}")

    async def _consensus_loop(self):
        """Periodically create new blocks"""
        while True:
            await asyncio.sleep(self.config.block_interval)
            async with self.consensus_lock:
                if self.dag.pending_transactions:
                    new_block = await self._create_block()
                    if new_block:
                        self.dag.add_block(new_block)
                        self.last_block_hash = new_block.hash
                        await self._broadcast_block(new_block)

    async def _create_block(self) -> Optional[Block]:
        """Create new block from pending transactions"""
        transactions = self.dag.get_pending_transactions(
            max_size=self.config.block_size
        )
        if not transactions:
            return None

        merkle_root = MerkleTree([tx.hash for tx in transactions]).root
        previous_hash = self.last_block_hash or self.dag.last_block.hash

        block = Block(
            index=self.dag.last_block.index + 1,
            transactions=transactions,
            previous_hash=previous_hash,
            timestamp=int(time.time()),
            merkle_root=merkle_root,
            validator=self.wallet.address
        )
        block.sign(self.wallet.private_key)
        return block

    async def _broadcast_block(self, block: Block):
        """Broadcast new block to network"""
        block_data = block.serialize()
        signature = sign_data(block_data, self.wallet.private_key)
        message = {
            "type": "block",
            "data": block_data,
            "signature": signature,
            "node_id": self.id,
            "timestamp": int(time.time())
        }
        await self._secure_broadcast(message)

    async def _secure_broadcast(self, message: dict):
        """Broadcast with end-to-end encryption"""
        message_json = json.dumps(message)
        async with self.peers_lock:
            for peer in list(self.peers):
                try:
                    if peer not in self.connection_pool:
                        conn = EncryptedConnection(peer[0], peer[1], self.pki)
                        await conn.establish()
                        self.connection_pool[peer] = conn
                    
                    conn = self.connection_pool[peer]
                    await conn.send_encrypted(message_json)
                except Exception as e:
                    log(f"Broadcast to {peer} failed: {e}")
                    await self._handle_failed_peer(peer)

    async def _handle_message(self, raw_message: str, addr: Tuple[str, int]):
        """Process incoming messages with security checks"""
        try:
            # Rate limiting
            if not self.rate_limiter.check_request(addr[0]):
                log(f"Rate limit exceeded for {addr}")
                return
            
            message = json.loads(raw_message)
            
            # Verify message signature
            if not self._verify_message_integrity(message):
                log("Message integrity check failed")
                return
                
            msg_type = message["type"]
            msg_timestamp = message["timestamp"]
            
            # Check message freshness
            if time.time() - msg_timestamp > self.config.msg_expiry:
                log("Expired message discarded")
                return
                
            # Message type handling
            if msg_type == "transaction":
                await self._handle_transaction(message, addr)
            elif msg_type == "peer_announce":
                await self._handle_peer_announce(message, addr)
            elif msg_type == "block":
                await self._handle_block(message, addr)
            elif msg_type == "sync_request":
                await self._handle_sync_request(message, addr)
            elif msg_type == "heartbeat":
                await self._handle_heartbeat(message, addr)
                
        except (json.JSONDecodeError, KeyError) as e:
            log(f"Invalid message format: {e}")
        except Exception as e:
            log(f"Message handling error: {e}")

    def _verify_message_integrity(self, message: dict) -> bool:
        """Verify digital signature of message"""
        required_fields = {"type", "data", "signature", "node_id", "timestamp"}
        if not all(field in message for field in required_fields):
            return False
            
        data_str = json.dumps(message["data"], sort_keys=True)
        return verify_signature(
            message["node_id"],
            data_str,
            message["signature"],
            self.pki
        )

    async def _handle_transaction(self, message: dict, addr: Tuple[str, int]):
        """Process incoming transaction"""
        try:
            tx_data = message["data"]
            tx = Transaction.from_dict(tx_data)
            
            # Check for replay attacks
            if self.ledger.is_transaction_processed(tx.hash):
                return
                
            # Validate transaction structure
            if not tx.validate_structure():
                return
                
            # Add to processing queue
            await self.pending_transactions.put(tx)
            
        except Exception as e:
            log(f"Transaction handling error: {e}")

    async def _handle_block(self, message: dict, addr: Tuple[str, int]):
        """Process incoming block"""
        try:
            block_data = message["data"]
            block = Block.deserialize(block_data)
            
            # Verify block signature
            if not block.verify_signature(self.pki):
                log("Block signature verification failed")
                return
                
            # Validate block with AI engine
            if not await self.validator_engine.validate_block(block):
                log("Block validation failed")
                return
                
            async with self.consensus_lock:
                # Add to DAG
                self.dag.add_block(block)
                self.ledger.update_state(block)
                self.last_block_hash = block.hash
                
                # Propagate to network
                await self._secure_broadcast(message)
                
        except Exception as e:
            log(f"Block handling error: {e}")

    async def _handle_peer_announce(self, message: dict, addr: Tuple[str, int]):
        """Process peer announcement"""
        try:
            host = message["host"]
            port = message["port"]
            peer_id = message["node_id"]
            
            # Avoid self-connection
            if peer_id == self.id:
                return
                
            # Validate peer information
            if not self._validate_peer_address(host, port):
                return
                
            peer = (host, port)
            
            async with self.peers_lock:
                if peer not in self.peers:
                    self.peers.add(peer)
                    log(f"New peer added: {peer}")
                    
        except Exception as e:
            log(f"Peer announce error: {e}")

    def _validate_peer_address(self, host: str, port: int) -> bool:
        """Validate peer network address"""
        # Prevent localhost exploitation
        if host in ["127.0.0.1", "localhost", "::1"] and not self.config.allow_local:
            return False
            
        # Validate port range
        if not (1024 < port < 65535):
            return False
            
        return True

    async def _handle_failed_peer(self, peer: Tuple[str, int]):
        """Handle failed peer connection"""
        async with self.peers_lock:
            if peer in self.peers:
                self.peers.remove(peer)
                
            if peer in self.connection_pool:
                await self.connection_pool[peer].close()
                del self.connection_pool[peer]
                
            self.blacklist.add(peer[0])

    async def _heartbeat(self):
        """Periodic peer health check"""
        while True:
            await asyncio.sleep(self.config.heartbeat_interval)
            await self._secure_broadcast({
                "type": "heartbeat",
                "node_id": self.id,
                "timestamp": int(time.time())
            })

    async def _handle_heartbeat(self, message: dict, addr: Tuple[str, int]):
        """Process heartbeat message"""
        peer_id = message["node_id"]
        log(f"Heartbeat from {peer_id}")

    async def _sync_blocks(self):
        """Periodically sync with network"""
        while True:
            await asyncio.sleep(self.config.sync_interval)
            if not self.peers:
                continue
                
            # Select random peer for syncing
            async with self.peers_lock:
                peer = secrets.choice(list(self.peers))
                
            try:
                # Request blocks since last known
                sync_msg = {
                    "type": "sync_request",
                    "from_hash": self.last_block_hash,
                    "node_id": self.id,
                    "timestamp": int(time.time())
                }
                await self._send_direct(peer, sync_msg)
            except Exception as e:
                log(f"Sync failed: {e}")
                await self._handle_failed_peer(peer)

    async def _handle_sync_request(self, message: dict, addr: Tuple[str, int]):
        """Handle block synchronization request"""
        try:
            from_hash = message["from_hash"]
            blocks = self.dag.get_blocks_since(from_hash)
            
            for block in blocks:
                block_data = block.serialize()
                signature = sign_data(block_data, self.wallet.private_key)
                response = {
                    "type": "block",
                    "data": block_data,
                    "signature": signature,
                    "node_id": self.id,
                    "timestamp": int(time.time())
                }
                await self._send_direct(addr, response)
                
        except Exception as e:
            log(f"Sync request handling error: {e}")

    async def _send_direct(self, addr: Tuple[str, int], message: dict):
        """Send message directly to specific peer"""
        try:
            if addr not in self.connection_pool:
                conn = EncryptedConnection(addr[0], addr[1], self.pki)
                await conn.establish()
                self.connection_pool[addr] = conn
                
            await self.connection_pool[addr].send_encrypted(json.dumps(message))
        except Exception as e:
            log(f"Direct send to {addr} failed: {e}")
            await self._handle_failed_peer(addr)

    async def announce_self(self):
        """Announce node presence to network"""
        message = {
            "type": "peer_announce",
            "host": self.host,
            "port": self.port,
            "node_id": self.id,
            "timestamp": int(time.time())
        }
        signature = sign_data(
            json.dumps({"host": self.host, "port": self.port}),
            self.wallet.private_key
        )
        message["signature"] = signature
        await self._secure_broadcast(message)

    async def submit_transaction(self, tx_data: dict):
        """Submit new transaction to network"""
        try:
            tx = Transaction.from_dict(tx_data)
            tx.sign(self.wallet.private_key)
            
            if not self.validator_engine.validate_transaction(tx):
                raise ValueError("Invalid transaction")
                
            await self.pending_transactions.put(tx)
            return tx.hash
        except Exception as e:
            log(f"Transaction submission failed: {e}")
            raise

    def get_network_info(self) -> dict:
        """Return network information"""
        return {
            "node_id": self.id,
            "version": self.config.version,
            "peers": len(self.peers),
            "last_block": self.last_block_hash,
            "pending_txs": self.pending_transactions.qsize(),
            "state_hash": self.ledger.state_hash
        }

    async def shutdown(self):
        """Graceful shutdown procedure"""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        if self.sync_task:
            self.sync_task.cancel()
            
        # Close all connections
        for conn in self.connection_pool.values():
            await conn.close()
            
        await self.server.stop()
