from pathlib import Path

# === FILE 1: README.md ===
readme_en = """
# 🔁 Repeater Chain

Repeater Chain is a next-generation blockchain protocol based on **DAG** (Directed Acyclic Graph) and **autonomous AI validation**, built for ultra-fast throughput, zero human validators, and mathematically structured consensus.

---

## ⚙️ Key Features

| Feature                   | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| ⚡ DAG Hashgraph          | Parallel and efficient structure for transaction blocks                     |
| 🤖 AI Validator           | Autonomous node validator with ML + rule engine hybrid                     |
| 🔐 Hash-Based Login       | Wallet access via password → hash → authentication                          |
| 🧠 AI-enhanced PBFT       | Byzantine consensus guided by AI confidence scoring                        |
| 🧬 zk-SNARK Compression   | Compact transaction format using zero-knowledge proof logic                |
| 🔄 WASM Smart Contracts   | Ultra-light execution with WebAssembly + AI opcodes                        |
| 🌐 Dynamic P2P Network    | Libp2p-like protocol with IP rotation and NTRU encryption                  |

---

## 🔬 Mathematical Design

The project treats data not as bytes, but as dynamic structures. Each change in user state generates a new block (not mutation), which:

- Forms a DAG instead of linear chain
- Limits active blocks to N (default: 10)
- Ensures compressed + verifiable transitions
- Prevents double spending and ensures rollback-free consensus

### Hash-Login System

A user password (e.g. `admin123`) is hashed once (SHA3_256) → becomes private key.  
The hash of that hash (double hash) is stored and used to verify login.  
Result: no seed phrase, no private key stored, zero leakage.

---

## 🧠 AI Validator Mechanism

- **Model**: TensorFlow Lite (for edge performance)
- **Detection**: Anomaly scoring, transaction abuse, DDoS patterns
- **Reputation**: Each node carries a confidence weight, trained and penalized

---

## 🧱 Project Structure

