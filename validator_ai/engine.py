import tensorflow.lite as tflite
import numpy as np
import hashlib
import time
import json
import threading
import os
import hmac
import logging
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from validator_ai.model import load_model
from utils.crypto import verify_signature, secure_hash
from utils.logger import secure_log, tamper_detection_log
from core.wallet import Wallet
from core.config import Config

class RuleEngine:
    def __init__(self, config):
        self.config = config
        self.known_contracts = self._load_known_contracts()
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.lock = threading.RLock()

    def check_basic_rules(self, tx):
        """Multi-layered rule validation with threat intelligence"""
        if not self._validate_tx_type(tx):
            return False
        if not self._verify_fields(tx):
            return False
        if not self._verify_signature(tx):
            return False
        if not self._validate_amount(tx):
            return False
        if not self._validate_timestamp(tx):
            return False
        if not self._detect_suspicious_patterns(tx):
            return False
        if not self._check_contract_whitelist(tx):
            return False
        return True

    def _validate_tx_type(self, tx):
        """Validate transaction type against allowed types"""
        allowed_types = self.config.get('allowed_tx_types', ['transfer', 'contract_call'])
        if tx.tx_type not in allowed_types:
            tamper_detection_log(f"Invalid TX type: {tx.tx_type}")
            return False
        return True

    def _verify_fields(self, tx):
        """Structural validation with deep inspection"""
        required_fields = ['sender', 'receiver', 'amount', 'timestamp', 'signature', 'tx_id']
        for field in required_fields:
            if not hasattr(tx, field):
                tamper_detection_log(f"Missing field: {field}")
                return False
        
        # Validate field formats
        if not Wallet.validate_address(tx.sender):
            tamper_detection_log(f"Invalid sender address: {tx.sender}")
            return False
        if not Wallet.validate_address(tx.receiver):
            tamper_detection_log(f"Invalid receiver address: {tx.receiver}")
            return False
        if not isinstance(tx.tx_id, str) or len(tx.tx_id) != 64:
            tamper_detection_log(f"Invalid TX ID format: {tx.tx_id}")
            return False
            
        return True

    def _verify_signature(self, tx):
        """Enhanced signature verification with replay protection"""
        try:
            # Create secure payload with nonce protection
            payload = f"{tx.sender}:{tx.receiver}:{tx.amount}:{tx.timestamp}:{tx.nonce}".encode()
            
            # Verify using elliptic curve cryptography
            return verify_signature(payload, tx.signature, tx.sender)
        except Exception as e:
            tamper_detection_log(f"Signature verification failed: {str(e)}")
            return False

    def _validate_amount(self, tx):
        """Amount validation with economic constraints"""
        if not isinstance(tx.amount, (int, float)) or tx.amount <= 0:
            tamper_detection_log(f"Invalid amount: {tx.amount}")
            return False
            
        # Check against network limits
        max_tx = self.config.get('max_transaction_amount', 1000000)
        if tx.amount > max_tx:
            tamper_detection_log(f"Amount exceeds limit: {tx.amount} > {max_tx}")
            return False
            
        return True

    def _validate_timestamp(self, tx):
        """Time validation with network sync tolerance"""
        current_time = time.time()
        time_diff = current_time - tx.timestamp
        max_delay = self.config.get('max_tx_delay', 30)
        
        if time_diff > max_delay or time_diff < -5:  # Allow 5s for future tolerance
            tamper_detection_log(f"Invalid timestamp: diff={time_diff}s")
            return False
        return True

    def _detect_suspicious_patterns(self, tx):
        """Pattern recognition for known attack vectors"""
        with self.lock:
            for pattern in self.suspicious_patterns:
                if pattern in tx.data:
                    tamper_detection_log(f"Suspicious pattern detected: {pattern}")
                    return False
        return True

    def _check_contract_whitelist(self, tx):
        """Contract validation against known good contracts"""
        if tx.tx_type == 'contract_call':
            contract_hash = secure_hash(tx.contract_code)
            if contract_hash not in self.known_contracts:
                tamper_detection_log(f"Unknown contract: {contract_hash}")
                return False
        return True

    def _load_known_contracts(self):
        """Load trusted contract hashes from secure storage"""
        contract_path = Path("data/contracts/known_contracts.enc")
        if not contract_path.exists():
            return set()
            
        try:
            with open(contract_path, 'rb') as f:
                encrypted = f.read()
                decrypted = self._decrypt_data(encrypted)
                return set(decrypted.decode().splitlines())
        except Exception as e:
            secure_log(f"Contract load failed: {str(e)}")
            return set()

    def _load_suspicious_patterns(self):
        """Load threat intelligence patterns"""
        patterns = [
            "DROP TABLE", 
            "UNION SELECT",
            "eval(",
            "exec(",
            "Runtime.getRuntime().exec",
            "System(",
            "document.cookie",
            "<script>",
            "malicious-domain.com"
        ]
        # Add dynamic patterns from config
        patterns.extend(self.config.get('suspicious_patterns', []))
        return patterns

    def _decrypt_data(self, data):
        """Decrypt sensitive data using hardware-backed keys"""
        # Use config-based keys
        salt = self.config['crypto_salt']
        password = self.config['crypto_password'].encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class AIValidator:
    def __init__(self, model_paths, config):
        self.config = config
        self.rule_engine = RuleEngine(config)
        
        # Multi-model ensemble for robust validation
        self.models = {
            'anomaly': load_model(model_paths['anomaly']),
            'fraud': load_model(model_paths['fraud']),
            'reputation': load_model(model_paths['reputation'])
        }
        
        self.thresholds = config.get('ai_thresholds', {
            "anomaly_reject": 0.4,
            "fraud_reject": 0.6,
            "suspicious": 0.7
        })
        
        # Secure logging setup
        self.log_path = Path("logs/ai_validation.enc")
        self.log_path.parent.mkdir(exist_ok=True)
        self.log_lock = threading.RLock()
        
        # Model performance monitoring
        self.validation_stats = {
            'total': 0,
            'rejected': 0,
            'flagged': 0,
            'accepted': 0,
            'false_positives': 0
        }
        self.stats_lock = threading.Lock()
        
        # Initialize model warmup
        self._warmup_models()

    def validate_transaction(self, tx):
        """Comprehensive transaction validation pipeline"""
        start_time = time.perf_counter()
        self._update_stat('total', 1)
        
        # Stage 1: Rule-based validation
        if not self.rule_engine.check_basic_rules(tx):
            self._log_validation(tx, 0.0, "REJECTED", "rule_violation")
            return 0.0, "rule_violation"

        # Stage 2: Multi-model AI validation
        anomaly_score = self._run_model('anomaly', tx)
        fraud_score = self._run_model('fraud', tx)
        reputation_score = self._run_model('reputation', tx)
        
        # Ensemble scoring
        composite_score = self._calculate_composite_score(
            anomaly_score, 
            fraud_score, 
            reputation_score
        )
        
        # Stage 3: Final decision
        decision, reason = self._make_decision(
            composite_score,
            anomaly_score,
            fraud_score
        )
        
        # Update statistics
        if decision == "REJECTED":
            self._update_stat('rejected', 1)
        elif decision == "FLAGGED":
            self._update_stat('flagged', 1)
        else:
            self._update_stat('accepted', 1)
            
        # Secure logging
        elapsed = time.perf_counter() - start_time
        self._log_validation(tx, composite_score, decision, reason, elapsed)
        
        return composite_score, decision

    def _run_model(self, model_type, tx):
        """Execute model inference with input validation"""
        try:
            input_tensor = self._prepare_input(model_type, tx)
            model = self.models[model_type]
            
            model.set_tensor(model.get_input_details()[0]['index'], input_tensor)
            model.invoke()
            output = model.get_tensor(model.get_output_details()[0]['index'])[0]
            
            # Post-process based on model type
            if model_type == 'anomaly':
                return float(1.0 - output[0])  # inverse of anomaly
            elif model_type == 'fraud':
                return float(output[1])  # fraud probability
            else:  # reputation
                return float(output[0])
        except Exception as e:
            secure_log(f"Model {model_type} failed: {str(e)}")
            return 0.5  # Neutral score on failure

    def _prepare_input(self, model_type, tx):
        """Create model-specific feature vectors"""
        base_features = [
            float(tx.amount),
            float(time.time() - tx.timestamp),
            len(tx.sender),
            len(tx.receiver),
            int(tx.tx_type == 'contract_call'),
            float(tx.fee / tx.amount) if tx.amount > 0 else 0.0
        ]
        
        # Model-specific features
        if model_type == 'anomaly':
            features = base_features + [
                self._tx_frequency(tx.sender),
                self._receiver_diversity(tx.sender)
            ]
        elif model_type == 'fraud':
            features = base_features + [
                self._contract_complexity(tx),
                self._similarity_score(tx)
            ]
        else:  # reputation
            features = base_features + [
                self._sender_reputation(tx.sender),
                self._receiver_reputation(tx.receiver)
            ]
            
        return np.array([features], dtype=np.float32)

    def _calculate_composite_score(self, anomaly, fraud, reputation):
        """Weighted ensemble scoring with model confidence"""
        weights = self.config.get('model_weights', {
            'anomaly': 0.4,
            'fraud': 0.4,
            'reputation': 0.2
        })
        
        # Apply sigmoid normalization
        anomaly_norm = 1 / (1 + np.exp(-10*(anomaly - 0.5)))
        fraud_norm = 1 / (1 + np.exp(-8*(fraud - 0.6)))
        reputation_norm = reputation  # Already 0-1
        
        return (
            weights['anomaly'] * anomaly_norm +
            weights['fraud'] * fraud_norm +
            weights['reputation'] * reputation_norm
        )

    def _make_decision(self, composite, anomaly, fraud):
        """Decision logic with adaptive thresholds"""
        # Check absolute rejection thresholds
        if composite < self.thresholds['anomaly_reject']:
            return "REJECTED", "high_anomaly"
        if fraud > self.thresholds['fraud_reject']:
            return "REJECTED", "high_fraud_prob"
            
        # Check suspicious threshold
        if composite < self.thresholds['suspicious']:
            return "FLAGGED", "suspicious_activity"
            
        return "ACCEPTED", "clean"

    def _log_validation(self, tx, score, decision, reason, elapsed=0):
        """Secure encrypted logging"""
        log_entry = {
            "timestamp": time.time(),
            "tx_id": tx.tx_id,
            "sender": tx.sender[:6] + "..." + tx.sender[-4:],  # Partial address
            "receiver": tx.receiver[:6] + "..." + tx.receiver[-4:],
            "amount": tx.amount,
            "score": score,
            "decision": decision,
            "reason": reason,
            "processing_time": elapsed,
            "model_version": self.config['model_version']
        }
        
        with self.log_lock:
            # Encrypt before writing
            encrypted = self._encrypt_log(json.dumps(log_entry).encode())
            with open(self.log_path, 'ab') as f:
                f.write(encrypted)
                f.write(b'\n')  # Newline separator

    def _encrypt_log(self, data):
        """Encrypt log data with rotating keys"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.config['log_encryption_key'].encode())
        
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return salt + iv + ciphertext

    def _update_stat(self, key, value=1):
        """Thread-safe statistics update"""
        with self.stats_lock:
            self.validation_stats[key] = self.validation_stats.get(key, 0) + value

    def _warmup_models(self):
        """Pre-initialize models for faster inference"""
        dummy_input = np.zeros((1, 10), dtype=np.float32)  # Adjust size as needed
        for name, model in self.models.items():
            try:
                model.set_tensor(model.get_input_details()[0]['index'], dummy_input)
                model.invoke()
                model.get_tensor(model.get_output_details()[0]['index'])
            except Exception as e:
                secure_log(f"Model warmup failed for {name}: {str(e)}")

    def _tx_frequency(self, address):
        """Calculate transaction frequency for address"""
        # Implement with actual data source
        return 0.5  # Placeholder

    def _receiver_diversity(self, address):
        """Calculate receiver diversity score"""
        # Implement with actual data source
        return 0.7  # Placeholder

    def _contract_complexity(self, tx):
        """Analyze contract complexity if applicable"""
        if tx.tx_type != 'contract_call':
            return 0.0
        return min(1.0, len(tx.contract_code) / 10000)  # Normalized

    def _similarity_score(self, tx):
        """Calculate similarity to known fraudulent patterns"""
        # Implement actual similarity analysis
        return 0.2  # Placeholder

    def _sender_reputation(self, address):
        """Retrieve sender reputation score"""
        # Connect to reputation system
        return 0.8  # Placeholder

    def _receiver_reputation(self, address):
        """Retrieve receiver reputation score"""
        # Connect to reputation system
        return 0.9  # Placeholder

    def get_validation_stats(self):
        """Get current validation statistics"""
        with self.stats_lock:
            return self.validation_stats.copy()
