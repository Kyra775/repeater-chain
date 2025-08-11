import asyncio
import statistics
import time
import uuid
import logging
import hashlib
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum, auto
from collections import defaultdict

from core.transaction import Transaction
from core.state import Ledger
from validator_ai.engine import hybrid_validation
from validator_ai.reputation import ReputationManager
from network.node import broadcast_score, broadcast_vote
from utils.hashing import hash_transaction_bundle
from utils.logger import log_event, tamper_proof_log
from utils.compression import compress_tx
from utils.crypto import verify_vote_signature
from core.config import Config
from core.exceptions import ConsensusException

logger = logging.getLogger(__name__)

class ConsensusStatus(Enum):
    """Enhanced consensus status with additional states"""
    PENDING = auto()
    VALIDATED = auto()
    REJECTED = auto()
    FINALIZED = auto()
    DISPUTED = auto()
    TIMED_OUT = auto()
    INCONSISTENT = auto()

class ConsensusResult:
    """Enhanced consensus result with additional metadata"""
    def __init__(self, 
                 status: ConsensusStatus, 
                 score: float, 
                 validators: List[str],
                 bundle_hash: Optional[str] = None,
                 signatures: Optional[Dict[str, str]] = None):
        self.status = status
        self.score = score
        self.validators = validators
        self.timestamp = time.time()
        self.bundle_hash = bundle_hash or self._calculate_bundle_hash()
        self.signatures = signatures or {}
        self.evidence = {}
        self.consensus_round = 0

    def _calculate_bundle_hash(self) -> str:
        """Calculate bundle hash for integrity verification"""
        return hashlib.sha256(str(self.timestamp).encode()).hexdigest()

    def add_evidence(self, evidence_type: str, data: Dict):
        """Add supporting evidence to the consensus result"""
        self.evidence[evidence_type] = data

    def verify_signatures(self, public_keys: Dict[str, str]) -> bool:
        """Verify all validator signatures"""
        if not self.signatures:
            return False
            
        for validator, signature in self.signatures.items():
            pub_key = public_keys.get(validator)
            if not pub_key or not verify_vote_signature(
                self.bundle_hash, signature, pub_key
            ):
                return False
        return True

@dataclass
class ConsensusMetrics:
    """Detailed consensus performance metrics"""
    validation_times: List[float] = field(default_factory=list)
    vote_collection_times: List[float] = field(default_factory=list)
    bundle_sizes: List[int] = field(default_factory=list)
    peer_latencies: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    error_rates: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

class BFTConsensusEngine:
    """Enhanced BFT Consensus Engine with additional security and performance features"""
    
    def __init__(self, node_id: str, config: Config):
        self.node_id = node_id
        self.config = config
        self.reputation = ReputationManager()
        self.ledger = Ledger()
        
        # Enhanced data structures
        self.votes: Dict[str, Dict[str, Tuple[bool, float]]] = defaultdict(dict)
        self.decisions: Dict[str, ConsensusResult] = {}
        self.pending_bundles: Set[str] = set()
        
        # Configurable parameters with defaults
        self.timeout = config.get('bft_timeout', 5)
        self.vote_threshold = config.get('vote_threshold', 0.66)
        self.confidence_threshold = config.get('confidence_threshold', 0.9)
        self.max_retries = config.get('max_retries', 3)
        self.min_peers = config.get('min_peers', 4)
        
        # Performance tracking
        self.metrics = ConsensusMetrics()
        self._last_cleanup = time.time()
        
        # Security features
        self.verified_peers: Set[str] = set()
        self.blacklist: Set[str] = set()
        
        logger.info(f"Initialized BFT Consensus Engine (Node {self.node_id})")

    async def process_bundle(self, 
                           tx_bundle: List[Transaction], 
                           bundle_id: str = None,
                           is_retry: bool = False) -> ConsensusResult:
        """Enhanced bundle processing with retry logic and security checks"""
        if not tx_bundle:
            raise ConsensusException("Empty transaction bundle")

        bundle_id = bundle_id or self._generate_bundle_id(tx_bundle)
        
        if bundle_id in self.decisions and not is_retry:
            logger.warning(f"Bundle {bundle_id} already processed")
            return self.decisions[bundle_id]

        logger.info(f"Processing bundle {bundle_id} with {len(tx_bundle)} txs")
        start_time = time.time()
        
        try:
            # Security check: verify bundle integrity
            if not self._verify_bundle_integrity(tx_bundle, bundle_id):
                raise ConsensusException("Bundle integrity check failed")

            # Local validation with enhanced checks
            local_score = await self._local_validate(tx_bundle)
            self.metrics.validation_times.append(time.time() - start_time)
            
            # Broadcast score with reputation-based weighting
            weighted_score = self._apply_reputation_weight(local_score)
            await broadcast_score(bundle_id, weighted_score, self.node_id)

            # Collect and validate peer scores
            peer_scores = await self._collect_scores(bundle_id)
            all_scores = [local_score] + peer_scores
            
            # Make preliminary decision
            decision, confidence = self._validate_scores(all_scores)
            
            # Broadcast vote with cryptographic signature
            await self._broadcast_vote(bundle_id, decision, confidence)
            
            # Collect votes and finalize decision
            final_decision = await self._finalize_decision(
                bundle_id, decision, confidence, all_scores
            )
            
            # Apply transaction if validated
            if final_decision.status == ConsensusStatus.VALIDATED:
                self._finalize_bundle(tx_bundle, bundle_id)
                final_decision.status = ConsensusStatus.FINALIZED

            return final_decision
            
        except Exception as e:
            logger.error(f"Consensus failed for bundle {bundle_id}: {str(e)}")
            self.metrics.error_rates[str(type(e))] += 1
            
            if not is_retry and self.max_retries > 0:
                logger.info(f"Retrying bundle {bundle_id} ({self.max_retries} retries left)")
                self.max_retries -= 1
                return await self.process_bundle(tx_bundle, bundle_id, True)
            
            # Create error result
            result = ConsensusResult(
                status=ConsensusStatus.REJECTED,
                score=0.0,
                validators=[self.node_id]
            )
            result.add_evidence("error", {"type": str(type(e)), "message": str(e)})
            return result

    def _generate_bundle_id(self, tx_bundle: List[Transaction]) -> str:
        """Generate deterministic bundle ID from transactions"""
        tx_hashes = sorted(tx.hash() for tx in tx_bundle)
        return hashlib.sha256(''.join(tx_hashes).encode()).hexdigest()

    def _verify_bundle_integrity(self, tx_bundle: List[Transaction], bundle_id: str) -> bool:
        """Enhanced bundle integrity verification"""
        # Check for duplicate transactions
        tx_ids = {tx.hash() for tx in tx_bundle}
        if len(tx_ids) != len(tx_bundle):
            logger.warning("Duplicate transactions in bundle")
            return False
            
        # Verify cryptographic hashes
        for tx in tx_bundle:
            if not tx.verify_hash():
                logger.warning(f"Invalid transaction hash: {tx.hash()}")
                return False
                
        # Additional checks could include:
        # - Merkle tree verification
        # - Signature batch verification
        # - Temporal consistency checks
        
        return True

    async def _local_validate(self, tx_bundle: List[Transaction]) -> float:
        """Enhanced local validation with additional checks"""
        # Perform hybrid validation (AI + rules)
        score = hybrid_validation(tx_bundle)
        
        # Additional validation steps
        if not self._check_transaction_dependencies(tx_bundle):
            score *= 0.5  # Penalize for missing dependencies
            
        if self._detect_conflicts(tx_bundle):
            score *= 0.3  # Penalize for conflicts
            
        logger.debug(f"Local validation score: {score:.3f}")
        return max(0.0, min(1.0, score))  # Ensure score is in [0, 1] range

    async def _collect_scores(self, bundle_id: str) -> List[float]:
        """Enhanced score collection with peer verification"""
        start_time = time.time()
        scores = []
        collected_peers = set()

        while time.time() - start_time < self.timeout:
            await asyncio.sleep(0.1)
            
            # Get new scores from verified peers
            new_scores = self._get_verified_peer_scores(bundle_id)
            for peer_id, score in new_scores:
                if peer_id not in collected_peers and peer_id != self.node_id:
                    scores.append(score)
                    collected_peers.add(peer_id)
                    self.metrics.peer_latencies[peer_id].append(time.time() - start_time)
            
            # Early termination if we have enough responses
            if len(collected_peers) >= self.min_peers:
                break

        collection_time = time.time() - start_time
        self.metrics.vote_collection_times.append(collection_time)
        self.metrics.bundle_sizes.append(len(collected_peers))
        
        logger.debug(f"Collected {len(scores)} peer scores in {collection_time:.2f}s")
        return scores

    def _get_verified_peer_scores(self, bundle_id: str) -> List[Tuple[str, float]]:
        """Get scores from verified peers (mock implementation)"""
        # In a real implementation, this would verify signatures and check reputation
        return [
            (f"peer_{i}", round(0.7 + 0.2 * (i % 3), 3)) 
            for i in range(self.min_peers)
        ]

    async def _broadcast_vote(self, 
                            bundle_id: str, 
                            decision: bool, 
                            confidence: float):
        """Enhanced vote broadcasting with cryptographic signatures"""
        vote_data = {
            "bundle_id": bundle_id,
            "decision": decision,
            "confidence": confidence,
            "timestamp": time.time(),
            "node_id": self.node_id
        }
        
        # In a real implementation, we would sign the vote
        signature = "mock_signature"  # Would be actual cryptographic signature
        
        await broadcast_vote(bundle_id, self.node_id, decision, confidence, signature)
        
        # Store our own vote
        self.votes[bundle_id][self.node_id] = (decision, confidence, signature)

    async def _finalize_decision(self,
                               bundle_id: str,
                               preliminary_decision: bool,
                               confidence: float,
                               scores: List[float]) -> ConsensusResult:
        """Finalize consensus decision with vote verification"""
        # Wait for votes to arrive
        await asyncio.sleep(0.5)  # Allow time for votes to propagate
        
        # Get all votes for this bundle
        all_votes = self.votes.get(bundle_id, {})
        
        # Verify votes and count decisions
        verified_votes = []
        for peer_id, (decision, peer_confidence, signature) in all_votes.items():
            if peer_id in self.blacklist:
                continue
                
            # In a real implementation, verify the signature here
            is_valid = True  # Placeholder for actual verification
            
            if is_valid:
                verified_votes.append((decision, peer_confidence))
                self.verified_peers.add(peer_id)
            else:
                logger.warning(f"Invalid vote signature from {peer_id}")
                self.blacklist.add(peer_id)
        
        # Calculate final decision
        if not verified_votes:
            return ConsensusResult(
                status=ConsensusStatus.TIMED_OUT,
                score=statistics.mean(scores),
                validators=[self.node_id]
            )
            
        agree_votes = sum(1 for d, _ in verified_votes if d == preliminary_decision)
        agree_ratio = agree_votes / len(verified_votes)
        
        mean_confidence = statistics.mean(c for _, c in verified_votes)
        mean_score = statistics.mean(scores)
        
        if agree_ratio >= self.vote_threshold and mean_confidence >= self.confidence_threshold:
            status = ConsensusStatus.VALIDATED if preliminary_decision else ConsensusStatus.REJECTED
        else:
            status = ConsensusStatus.DISPUTED
            
        # Prepare signatures for the result
        signatures = {
            peer_id: sig 
            for peer_id, (_, _, sig) in all_votes.items()
            if peer_id in self.verified_peers
        }
        
        return ConsensusResult(
            status=status,
            score=mean_score,
            validators=list(self.verified_peers),
            signatures=signatures
        )

    def _finalize_bundle(self, tx_bundle: List[Transaction], bundle_id: str):
        """Enhanced bundle finalization with additional checks"""
        logger.info(f"Finalizing bundle {bundle_id}")
        
        # Double-check all transactions before applying
        valid_txs = []
        for tx in tx_bundle:
            if tx.verify() and not self.ledger.has_transaction(tx.hash()):
                valid_txs.append(tx)
            else:
                logger.warning(f"Invalid or duplicate transaction {tx.hash()}")
        
        # Apply valid transactions
        for tx in valid_txs:
            self.ledger.apply_transaction(tx)
            tamper_proof_log("tx_finalized", {
                "bundle_id": bundle_id,
                "tx_id": tx.hash(),
                "sender": tx.sender,
                "receiver": tx.receiver,
                "value": tx.value,
                "timestamp": time.time()
            })

    def _check_transaction_dependencies(self, tx_bundle: List[Transaction]) -> bool:
        """Check if all transaction dependencies are satisfied"""
        # Implementation would check for required previous transactions
        return True

    def _detect_conflicts(self, tx_bundle: List[Transaction]) -> bool:
        """Detect conflicting transactions in the bundle"""
        # Implementation would check for double-spends or other conflicts
        return False

    def _apply_reputation_weight(self, score: float) -> float:
        """Apply reputation-based weighting to our score"""
        # Higher reputation nodes might have more weight
        reputation = self.reputation.get_score(self.node_id)
        return score * (0.9 + 0.1 * reputation)  # Adjust score by ±10% based on reputation

    def _validate_scores(self, scores: List[float]) -> Tuple[bool, float]:
        """Enhanced score validation with statistical analysis"""
        if not scores:
            return False, 0.0

        mean_score = statistics.mean(scores)
        stdev = statistics.stdev(scores) if len(scores) > 1 else 0.0
        strong_agreements = sum(s >= 0.8 for s in scores) / len(scores)
        weak_agreements = sum(s >= 0.5 for s in scores) / len(scores)

        logger.info(
            f"Consensus metrics - Mean: {mean_score:.3f}, "
            f"Stdev: {stdev:.3f}, "
            f"Strong: {strong_agreements:.2%}, "
            f"Weak: {weak_agreements:.2%}"
        )

        decision = (
            mean_score >= self.confidence_threshold and 
            strong_agreements >= self.vote_threshold and
            stdev < 0.2  # Prevent high variance in scores
        )
        
        return decision, mean_score

    def get_consensus_status(self, bundle_id: str) -> Tuple[ConsensusStatus, float]:
        """Get current status of a consensus process"""
        result = self.decisions.get(bundle_id)
        if not result:
            if bundle_id in self.pending_bundles:
                return ConsensusStatus.PENDING, 0.0
            return ConsensusStatus.REJECTED, 0.0
        return result.status, result.score

    def reset_state(self):
        """Reset engine state while preserving metrics"""
        self.votes.clear()
        self.decisions.clear()
        self.pending_bundles.clear()
        logger.info("Consensus engine state reset")

    def validate_vote_integrity(self, votes: Dict[str, List[str]]) -> bool:
        """Enhanced vote integrity validation"""
        for bid, validators in votes.items():
            # Check for duplicate votes
            if len(set(validators)) != len(validators):
                logger.warning(f"Duplicate votes detected for {bid}")
                return False
                
            # Check for blacklisted validators
            if any(v in self.blacklist for v in validators):
                logger.warning(f"Blacklisted validator in votes for {bid}")
                return False
                
        return True

    def summarize_consensus(self) -> Dict:
        """Enhanced consensus statistics with performance metrics"""
        stats = {
            "validated": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.VALIDATED),
            "rejected": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.REJECTED),
            "finalized": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.FINALIZED),
            "pending": len(self.pending_bundles),
            "disputed": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.DISPUTED),
            "timed_out": sum(1 for r in self.decisions.values() if r.status == ConsensusStatus.TIMED_OUT),
        }
        stats["total"] = sum(stats.values())
        
        # Add performance metrics
        stats.update({
            "avg_validation_time": statistics.mean(self.metrics.validation_times) if self.metrics.validation_times else 0,
            "avg_vote_collection_time": statistics.mean(self.metrics.vote_collection_times) if self.metrics.vote_collection_times else 0,
            "avg_bundle_size": statistics.mean(self.metrics.bundle_sizes) if self.metrics.bundle_sizes else 0,
            "error_rates": dict(self.metrics.error_rates),
        })
        
        return stats

    def cleanup_old_votes(self, ttl_seconds: int = 600):
        """Enhanced cleanup with metrics preservation"""
        now = time.time()
        expired = [
            bid for bid, result in self.decisions.items()
            if now - result.timestamp > ttl_seconds
        ]
        
        for bid in expired:
            self.votes.pop(bid, None)
            self.decisions.pop(bid, None)
            self.pending_bundles.discard(bid)
            
        logger.info(f"Cleaned {len(expired)} expired consensus results")
        self._last_cleanup = now

    def get_performance_metrics(self) -> Dict:
        """Get detailed performance metrics"""
        return {
            "validation_times": self.metrics.validation_times,
            "vote_collection_times": self.metrics.vote_collection_times,
            "bundle_sizes": self.metrics.bundle_sizes,
            "peer_latencies": dict(self.metrics.peer_latencies),
            "error_rates": dict(self.metrics.error_rates),
        }
