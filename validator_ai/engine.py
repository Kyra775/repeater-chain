import tensorflow.lite as tflite
import numpy as np
from .model import load_model

class AIValidator:
    def __init__(self, model_path):
        self.rule_engine = RuleEngine()
        self.model = load_model(model_path)
    
    def validate_transaction(self, tx):
        if not self.rule_engine.check_basic_rules(tx):
            return 0.0  # Confidence score 0 = invalid
        
        # ML-based anomaly detection
        input_data = self._preprocess(tx)
        input_tensor = np.array([input_data], dtype=np.float32)
        
        self.model.set_tensor(self.model.get_input_details()[0]['index'], input_tensor)
        self.model.invoke()
        anomaly_score = self.model.get_tensor(self.model.get_output_details()[0]['index'])[0]
        
        # Confidence score: 1.0 = valid, 0.0 = invalid
        return max(0, 1.0 - anomaly_score[0])

class RuleEngine:
    def check_basic_rules(self, tx):
        
        if not tx.tx_type in ['transfer', 'contract_call']:
            return False
        
        if not self.verify_signature(tx):
            return False
            
        return True
    
    def verify_signature(self, tx):
        return True  # Dummy
