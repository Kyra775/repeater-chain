# Interoperability in Repeater Chain

Repeater Chain supports cross-chain transactions and integration with Ethereum using a **Gateway Layer**.

---

## Gateway Layer Design

- The **repeater_bridge** module serves as an interoperability layer between Repeater Chain and external blockchains, such as Ethereum.
- It uses **web3.py** to interact with Ethereum smart contracts.

### Example Code: Mirror Ethereum Transaction

Below is an example function to mirror an Ethereum transaction into Repeater Chain's format:

```python

def mirror_eth_tx(tx_hash):
    # Fetch the Ethereum transaction
    eth_tx = eth_web3.eth.get_transaction(tx_hash)
    
    # Convert to Repeater Chain format
    repeater_tx = convert_to_repeater_format(eth_tx)
    return repeater_tx
```

---

## Future Plans

- **Wrapped Assets**:
  - Create "wrapped" tokens to represent Ethereum assets on Repeater Chain.

- **zk-Rollups**:
  - Use zk-rollup technology to batch external transactions for efficiency.