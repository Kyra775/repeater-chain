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


repeater_chain/
│
├── core/ # Core blockchain logic
│ ├── dag.py # DAG structure and block references
│ ├── transaction.py # One-line transactions and validation
│ ├── consensus.py # AI-BFT voting mechanism
│ ├── state.py # Account ledger and balance tracking
│ ├── wallet.py # Login with password → hash identity
│ └── config.py # Global configuration
│
├── validator_ai/ # AI-based validator engine
│ ├── engine.py # Hybrid rule + model decision system
│ ├── model.py # TensorFlow Lite model loader
│ ├── detection.py # Real-time fraud and anomaly detection
│ ├── reputation.py # AI-based node reputation
│ └── dataset/ # Training data for the model
│
├── network/ # Peer-to-peer network layer
│ ├── node.py # Node logic
│ ├── p2p_server.py # Async Python P2P server
│ ├── peer.go # Peer discovery (Go)
│ ├── protocol.go # Gossip and libp2p-style protocol (Go)
│ └── bindings/ # Python ↔ Go bridge
│ └── peer_bridge.py
│
├── runtime/ # Smart contract execution
│ ├── wasm_vm.rs # WebAssembly runtime (Rust)
│ ├── ai_opcode.rs # Custom opcode for AI verification
│ ├── executor.py # Interface to run contracts from Python
│ └── compiler.py # Rust → WASM compiler
│
├── data/
│ ├── mempool/ # Unconfirmed transactions
│ ├── chain/ # DAG chain stored in parquet
│ ├── models/ # Pre-trained AI models
│ └── snapshot/ # Periodic state backups
│
├── crypto_core/ # Native cryptographic operations
│ ├── schnorr.cpp # Schnorr signature implementation (C++)
│ ├── ntru.c # Post-quantum NTRU encryption
│ ├── password_hash.c # Password → hash → login logic
│ └── hash_map.cpp # Transaction/block hash mapping
│
├── utils/
│ ├── hashing.py # Python wrappers for crypto
│ ├── logger.py # Logging and anomaly alerts
│ ├── compression.py # zk-SNARK-style compression
│ └── ffi_loader.py # Load shared libraries from Python
│
├── api/
│ └── server.py # Optional gRPC/REST API interface
│
├── cli/
│ └── repeater.py # Command-line interface to run node
│
├── smart_contract/
│ ├── examples/ # Sample contracts (Rust → WASM)
│ └── verifier.rs # Smart contract signature verification
│
├── tests/
│ ├── test_dag.py
│ ├── test_wallet.py
│ ├── test_validator.py
│ └── test_network.py
│
├── docs/
│ ├── architecture.md
│ ├── crypto-design.md
│ ├── ai-consensus.md
│ └── login-mechanism.md
│
├── LICENSE
├── README.md
├── main.py # Entry point for node boot
├── requirements.txt # Python dependencies
├── Cargo.toml # Rust dependencies
├── go.mod # Go module definition
├── Makefile # Auto build for Rust/Go
└── .gitignore
