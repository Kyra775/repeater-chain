import asyncio
import json
import uuid
from network.p2p_server import P2PServer
from core.transaction import Transaction
from core.dag import DAG
from core.state import Ledger
from core.wallet import Wallet
from core.config import Config
from validator_ai.engine import ValidatorEngine
from utils.logger import log

class Node:
    def __init__(self, host: str, port: int):
        self.id = str(uuid.uuid4())
        self.host = host
        self.port = port
        self.peers = set()
        self.server = P2PServer(self)
        self.dag = DAG()
        self.ledger = Ledger()
        self.wallet = Wallet()
        self.config = Config()
        self.validator_engine = ValidatorEngine()

    async def start(self):
        await self.server.start(self.host, self.port)

    async def broadcast(self, message: dict):
        for peer in self.peers:
            try:
                reader, writer = await asyncio.open_connection(peer[0], peer[1])
                writer.write((json.dumps(message) + "\n").encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except:
                continue

    async def handle_message(self, message: dict):
        if message["type"] == "transaction":
            tx = Transaction.from_dict(message["data"])
            if self.validator_engine.validate_transaction(tx):
                self.dag.add_transaction(tx)
                self.ledger.apply_transaction(tx)
                await self.broadcast(message)

        elif message["type"] == "peer_announce":
            peer = (message["host"], message["port"])
            if peer not in self.peers and (peer[0], int(peer[1])) != (self.host, self.port):
                self.peers.add(peer)

        elif message["type"] == "block":
            block = self.dag.deserialize_block(message["data"])
            if self.validator_engine.validate_block(block):
                self.dag.add_block(block)
                self.ledger.update_state(block)

    def register_peer(self, host: str, port: int):
        peer = (host, int(port))
        if peer not in self.peers:
            self.peers.add(peer)

    async def announce_self(self):
        message = {
            "type": "peer_announce",
            "host": self.host,
            "port": self.port
        }
        await self.broadcast(message)

    async def submit_transaction(self, tx_data: dict):
        tx = Transaction.from_dict(tx_data)
        if self.validator_engine.validate_transaction(tx):
            self.dag.add_transaction(tx)
            self.ledger.apply_transaction(tx)
            await self.broadcast({
                "type": "transaction",
                "data": tx.to_dict()
            })

    def get_peers(self):
        return list(self.peers)
