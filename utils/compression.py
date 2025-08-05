def compress_tx(metadata):
    zk_proof = generate_zk_snark(metadata)
    return f"{metadata['type']}:{metadata['from'][:8]}...{zk_proof}"
