class HashgraphDAG:
    def __init__(self):
        self.graph = {}  
        self.tips = set()

    def add_node(self, tx_bundle, ai_confidence):
        
        if ai_confidence > config.AI_THRESHOLD:
            
