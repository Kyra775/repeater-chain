# consensus.py

import asyncio
import statistics
import time
import uuid
import logging
from typing import List, Dict, Tuple

from core.transaction import Transaction
from core.state import Ledger
from validator_ai.engine import hybrid_validation
from validator_ai.reputation import ReputationManager
from network.node import broadcast_score, broadcast_vote
from utils.hashing import hash_transaction_bundle
from utils.logger import log_event
from utils.compression import compress_tx
from core.config import Config

logger = logging.getLogger(__name__)

class ConsensusStatus:
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    FINALIZED = "FINALIZED"

class ConsensusResult:
    def __init__(self, status, score, validators):
        self.status = status
        self.score = score
        self.validators = validators
        self.timestamp = time.time()

class BFTConsensusEngine:
    def __init__(self, node_id: str, config: Config):
        self.node_id = node_id
        self.config = config
        self.reputation = ReputationManager()
        self.ledger = Ledger()
        self.votes: Dict[str, List[float]] = {}
        self.decisions: Dict[str, ConsensusResult] = {}
        self.timeout = config.bft_timeout or 5
        self.vote_threshold = 0.66
        self.confidence_threshold = 0.9

    async def process_bundle(self, tx_bundle: List[Transaction], bundle_id: str = None) -> ConsensusResult:
        bundle_id = bundle_id or str(uuid.uuid4())
        logger.info(f"[CONSENSUS] Processing transaction bundle {bundle_id} with {len(tx_bundle)} txs")

        local_score = await self._local_validate(tx_bundle)
        await broadcast_score(bundle_id, local_score)

        peer_scores = await self._collect_scores(bundle_id)
        all_scores = peer_scores + [local_score]

        if self._validate_scores(all_scores):
            await self._broadcast_vote(bundle_id, True)
            result = ConsensusResult(ConsensusStatus.VALIDATED, statistics.mean(all_scores), list(set(self.votes[bundle_id])))
        else:
            await self._broadcast_vote(bundle_id, False)
            result = ConsensusResult(ConsensusStatus.REJECTED, statistics.mean(all_scores), list(set(self.votes[bundle_id])))

        self.decisions[bundle_id] = result

        if result.status == ConsensusStatus.VALIDATED:
            self._finalize_bundle(tx_bundle, bundle_id)
            result.status = ConsensusStatus.FINALIZED

        return result

    async def _local_validate(self, tx_bundle: List[Transaction]) -> float:
        score = hybrid_validation(tx_bundle)
        logger.debug(f"[CONSENSUS] Local validation score: {score:.3f}")
        return score

    async def _collect_scores(self, bundle_id: str) -> List[float]:
        start_time = time.time()
        scores = []

        while time.time() - start_time < self.timeout:
            await asyncio.sleep(0.1)
            new_scores = self._get_peer_scores(bundle_id)
            scores.extend(new_scores)
            if len(scores) >= 3:
                break

        logger.debug(f"[CONSENSUS] Collected {len(scores)} peer scores")
        return scores

    def _get_peer_scores(self, bundle_id: str) -> List[float]:
        # Placeholder for actual network input
        return [round(0.8 + 0.1 * (i % 3), 3) for i in range(3)]

    async def _broadcast_vote(self, bundle_id: str, decision: bool):
        await broadcast_vote(bundle_id, self.node_id, decision)
        if bundle_id not in self.votes:
            self.votes[bundle_id] = []
        self.votes[bundle_id].append(self.node_id)

    def _validate_scores(self, scores: List[float]) -> bool:
        if not scores:
            return False

        mean_score = statistics.mean(scores)
        strong_agreements = sum(s >= 0.8 for s in scores) / len(scores)

        logger.info(f"[CONSENSUS] Mean score: {mean_score:.3f}, strong agreements: {strong_agreements:.2%}")
        return mean_score >= self.confidence_threshold and strong_agreements >= self.vote_threshold

    def _finalize_bundle(self, tx_bundle: List[Transaction], bundle_id: str):
        logger.info(f"[CONSENSUS] Finalizing bundle {bundle_id}")
        for tx in tx_bundle:
            self.ledger.apply_transaction(tx)
            log_event("tx_finalized", {
                "bundle_id": bundle_id,
                "tx_id": tx.hash(),
                "sender": tx.sender,
                "receiver": tx.receiver,
                "value": tx.value
            })

    def get_consensus_status(self, bundle_id: str) -> Tuple[str, float]:
        result = self.decisions.get(bundle_id)
        if not result:
            return ConsensusStatus.PENDING, 0.0
        return result.status, result.score

    def reset_state(self):
        self.votes.clear()
        self.decisions.clear()

    def validate_vote_integrity(self, votes: Dict[str, List[str]]) -> bool:
        for bid, validators in votes.items():
            if len(set(validators)) != len(validators):
                logger.warning(f"[CONSENSUS] Duplicate votes detected for {bid}")
                return False
        return True

    def summarize_consensus(self) -> Dict:
        stats = {
            "validated": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.VALIDATED),
            "rejected": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.REJECTED),
            "finalized": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.FINALIZED),
            "pending": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.PENDING),
        }
        stats["total"] = sum(stats.values())
        return stats

    def cleanup_old_votes(self, ttl_seconds: int = 600):
        now = time.time()
        expired = [bid for bid, result in self.decisions.items()
                   if now - result.timestamp > ttl_seconds]
        for bid in expired:
            self.votes.pop(bid, None)
            self.decisions.pop(bid, None)
        logger.info(f"[CONSENSUS] Cleaned {len(expired)} expired consensus results")
