def hybrid_validation(tx):
    if not rule_check(tx):
        return 0.0  
    
    input_data = preprocess(tx)
    anomaly_score = model.predict(input_data)
    
    return max(0, 1 - anomaly_score) 

def rule_check(tx):
    return crypto.verify_signature(tx)
