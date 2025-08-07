import tensorflow.lite as tflite
import numpy as np
import hashlib
import time
from .model import load_model

class RuleEngine:
    def check_basic_rules(self, tx):
        if tx.tx_type not in ['transfer', 'contract_call']:
            return False
        if not self._verify_fields(tx):
            return False
        if not self._verify_signature(tx):
            return False
        return True

    def _verify_fields(self, tx):
        required_fields = ['sender', 'receiver', 'amount', 'timestamp', 'signature']
        for field in required_fields:
            if not hasattr(tx, field):
                return False
        if not isinstance(tx.amount, (int, float)) or tx.amount <= 0:
            return False
        if time.time() - tx.timestamp > 30:
            return False
        return True

    def _verify_signature(self, tx):
        try:
            payload = f"{tx.sender}:{tx.receiver}:{tx.amount}:{tx.timestamp}".encode()
            expected_sig = hashlib.sha256(payload).hexdigest()
            return expected_sig == tx.signature
        except:
            return False

class AIValidator:
    def __init__(self, model_path, threshold=0.7):
        self.model = load_model(model_path)
        self.rule_engine = RuleEngine()
        self.threshold = threshold

    def validate_transaction(self, tx):
        if not self.rule_engine.check_basic_rules(tx):
            return 0.0

        input_tensor = self._prepare_input(tx)
        self.model.set_tensor(self.model.get_input_details()[0]['index'], input_tensor)
        self.model.invoke()
        output = self.model.get_tensor(self.model.get_output_details()[0]['index'])[0]
        score = float(1.0 - output[0])
        if score < self.threshold:
            self._handle_suspicious(tx, score)
        return score

    def _prepare_input(self, tx):
        features = [
            float(tx.amount),
            float(time.time() - tx.timestamp),
            len(str(tx.sender)),
            len(str(tx.receiver)),
            int(tx.tx_type == 'contract_call')
        ]
        return np.array([features], dtype=np.float32)

    def _handle_suspicious(self, tx, score):
        log_data = {
            "sender": tx.sender,
            "receiver": tx.receiver,
            "amount": tx.amount,
            "timestamp": tx.timestamp,
            "score": score
        }
        with open("suspicious_tx.log", "a") as f:
            f.write(str(log_data) + "\n")
