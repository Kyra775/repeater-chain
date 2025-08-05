async def ai_bft_consensus(tx_bundle):
    # Fase 1: Validasi lokal oleh AI
    local_score = validator_ai.engine.hybrid_validation(tx_bundle)
    
    # Fase 2: Broadcast score ke network
    scores = await network.broadcast_score(tx_bundle.id, local_score)
    
    # Hitung konsensus
    if mean(scores) > 0.9 and sum(s >= 0.8 for s in scores) > 2/3:
        finalize_transaction(tx_bundle)
