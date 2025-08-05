from pathlib import Path

# === FILE 1: README.md (English) ===
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
├── core/                                # Logika blockchain utama
│   ├── dag.py                           # Struktur DAG + block reference
│   ├── transaction.py                   # Transaksi ringkas + validasi
│   ├── consensus.py                     # AI-BFT voting
│   ├── state.py                         # Ledger dan saldo user
│   ├── wallet.py                        # Login via password → hashed identity
│   └── config.py                        # Konfigurasi sistem global
│
├── validator_ai/                        # Mesin AI validator
│   ├── engine.py                        # Rule + model hybrid
│   ├── model.py                         # Load model (.tflite)
│   ├── detection.py                     # Deteksi fraud, DDoS, anomaly
│   ├── reputation.py                    # Reputasi node
│   └── dataset/                         # Dataset training AI
│
├── network/                             # Jaringan node & koneksi
│   ├── node.py                          # Node handler
│   ├── p2p_server.py                    # Server lokal async
│   ├── peer.go                          # Peer discovery (Go)
│   ├── protocol.go                      # Gossip protocol (Go)
│   └── bindings/                        # Python↔Go interop
│       └── peer_bridge.py
│
├── runtime/                             # Eksekusi transaksi dan smart contract
│   ├── wasm_vm.rs                       # WASM runtime (Rust)
│   ├── ai_opcode.rs                     # AI_VERIFY opcode
│   ├── executor.py                      # Interface ke Python
│   └── compiler.py                      # Kompilasi smart contract
│
├── data/
│   ├── mempool/                         # Transaksi pending
│   ├── chain/                           # Chain DAG format parquet
│   ├── models/                          # Model AI
│   └── snapshot/                        # Backup state periodik
│
├── crypto_core/                         # Keamanan inti (ditulis native)
│   ├── schnorr.cpp                      # Signature cepat & ringan (C++)
│   ├── ntru.c                           # Enkripsi kuat untuk transport
│   ├── password_hash.c                  # Konversi password → key → login
│   └── hash_map.cpp                     # Hash index untuk blok & transaksi
│
├── utils/
│   ├── hashing.py                       # Python wrapper untuk crypto_core
│   ├── logger.py                        # Logging & alert system
│   ├── compression.py                   # zk-SNARK kompresi dummy
│   └── ffi_loader.py                    # Load .so/.dll dari Python
│
├── api/
│   └── server.py                        # REST/gRPC interface (opsional)
│
├── cli/
│   └── repeater.py                      # Jalankan node dari CLI
│
├── smart_contract/
│   ├── examples/                        # Kontrak WASM contoh
│   └── verifier.rs                      # Signature verifier untuk kontrak
│
├── tests/
│   ├── test_dag.py
│   ├── test_wallet.py
│   ├── test_validator.py
│   └── test_network.py
│
├── docs/
│   ├── architecture.md
│   ├── crypto-design.md
│   ├── ai-consensus.md
│   └── login-mechanism.md
│
├── LICENSE
├── README.md
├── main.py                              # Entry point dev/test node
├── requirements.txt                     # Dependensi Python
├── Cargo.toml                           # Build untuk Rust
├── go.mod                               # Build untuk Go
├── Makefile                             # Compile otomatis semua modul
└── .gitignore
