//! ai_opcode.rs
//!
//! Complex AI_VERIFY opcode implementation for Repeater Chain WASM runtime.
//! Comments intentionally minimal and focused on important parts only.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

// ----- Errors -----
#[derive(Error, Debug)]
pub enum AiError {
    #[error("model backend error: {0}")]
    ModelBackend(String),

    #[error("invalid opcode payload: {0}")]
    InvalidPayload(String),

    #[error("resource budget exceeded")]
    BudgetExceeded,

    #[error("verification failed")]
    VerificationFailed,

    #[error("internal error: {0}")]
    Internal(String),
}

// ----- Basic Types -----
/// Canonical input for AI_VERIFY; this is the deterministic representation derived from the VM/transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiVerifyInput {
    /// Raw payload (application-specific): must be canonicalized by the caller before entering opcode.
    pub payload: serde_json::Value,

    /// Model identifier (versioned)
    pub model_id: String,

    /// Optional tuning params (e.g. thresholds), are part of canonical input
    pub params: Option<serde_json::Value>,
}

/// Model output standardized by backend
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelOutput {
    pub score: f64,           // normalized [0.0, 1.0]
    pub label: Option<String>,
    pub raw: Option<serde_json::Value>,
}

/// Compact result returned to executor & stored in block (small, deterministic)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiVerifyResult {
    pub model_id: String,
    pub decision: bool,
    pub score: f64,
    pub label: Option<String>,
    pub timestamp_utc: String,
    pub proof_hash: String, // deterministic digest of (input,model_id,score,label)
}

// ----- Model Backend Trait (pluggable) -----
/// ModelBackend must produce deterministic outputs for the same canonical input.
/// Non-deterministic backends must produce verifiable proofs (out of scope here).
pub trait ModelBackend: Send + Sync {
    /// Run model inference on canonical input. Implementations may enforce budget/timeouts.
    fn infer(&self, input: &AiVerifyInput, budget_ms: u64) -> Result<ModelOutput>;
}

/// Simple in-memory deterministic model backend for testing/consensus-safe use.
/// It uses SHA-256 of the canonical payload to produce a stable pseudo-score and label.
pub struct InMemoryModelBackend {}

impl InMemoryModelBackend {
    pub fn new() -> Self {
        Self {}
    }

    /// Deterministic pseudo-inference: hash(payload|model_id|params) -> score & label
    fn deterministic_infer_raw(&self, input: &AiVerifyInput) -> ModelOutput {
        let mut hasher = Sha256::new();
        // canonical JSON serialization for determinism
        let payload_ser = serde_json::to_string(&input.payload).unwrap_or_default();
        hasher.update(payload_ser.as_bytes());
        hasher.update(b"||");
        hasher.update(input.model_id.as_bytes());
        if let Some(p) = &input.params {
            hasher.update(b"||");
            hasher.update(serde_json::to_string(p).unwrap_or_default().as_bytes());
        }
        let digest = hasher.finalize();
        // Use first 8 bytes to produce a deterministic float [0,1)
        let num = u64::from_be_bytes(digest[0..8].try_into().unwrap());
        let score = (num as f64) / (u64::MAX as f64);
        // choose a label deterministically
        let label = if score > 0.75 {
            Some("suspicious".to_string())
        } else if score > 0.45 {
            Some("neutral".to_string())
        } else {
            Some("benign".to_string())
        };
        ModelOutput {
            score,
            label: Some(label.unwrap()),
            raw: None,
        }
    }
}

impl ModelBackend for InMemoryModelBackend {
    fn infer(&self, input: &AiVerifyInput, _budget_ms: u64) -> Result<ModelOutput> {
        Ok(self.deterministic_infer_raw(input))
    }
}

// ----- Reputation Hook (optional) -----
pub trait ReputationHook: Send + Sync {
    fn record_verification(&self, subject: &str, success: bool, score: f64);
}

pub struct NoopReputation {}
impl ReputationHook for NoopReputation {
    fn record_verification(&self, _subject: &str, _success: bool, _score: f64) {}
}

// ----- Simple Cache with TTL -----
type CacheKey = String;
struct CacheEntry {
    result: AiVerifyResult,
    expires_at: Instant,
}

pub struct SimpleCache {
    map: RwLock<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
}

impl SimpleCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    fn key_for(input: &AiVerifyInput) -> String {
        // deterministic key: base64(sha256(canonical_json))
        let mut hasher = Sha256::new();
        let s = serde_json::to_string(input).unwrap_or_default();
        hasher.update(s.as_bytes());
        let digest = hasher.finalize();
        general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    pub fn get(&self, input: &AiVerifyInput) -> Option<AiVerifyResult> {
        let k = Self::key_for(input);
        let guard = self.map.read().unwrap();
        if let Some(entry) = guard.get(&k) {
            if Instant::now() <= entry.expires_at {
                return Some(entry.result.clone());
            }
        }
        None
    }

    pub fn insert(&self, input: &AiVerifyInput, value: AiVerifyResult) {
        let k = Self::key_for(input);
        let mut guard = self.map.write().unwrap();
        let entry = CacheEntry {
            result: value,
            expires_at: Instant::now() + self.ttl,
        };
        guard.insert(k, entry);
    }
}

// ----- AiVerifier: core opcode executor -----
/// Config for resource budgets and thresholds
#[derive(Clone, Debug)]
pub struct AiVerifierConfig {
    pub budget_ms: u64,
    pub cache_ttl_secs: u64,
    pub required_score_threshold: f64, // score >= threshold -> "suspicious" decision
    pub allow_cache: bool,
}

impl Default for AiVerifierConfig {
    fn default() -> Self {
        Self {
            budget_ms: 200,          // 200 ms budget by default
            cache_ttl_secs: 30,      // 30s cache TTL
            required_score_threshold: 0.75,
            allow_cache: true,
        }
    }
}

pub struct AiVerifier {
    backend: Arc<dyn ModelBackend>,
    reputation: Arc<dyn ReputationHook>,
    cache: SimpleCache,
    cfg: AiVerifierConfig,
}

impl AiVerifier {
    pub fn new(
        backend: Arc<dyn ModelBackend>,
        reputation: Arc<dyn ReputationHook>,
        cfg: AiVerifierConfig,
    ) -> Self {
        Self {
            backend,
            reputation,
            cache: SimpleCache::new(Duration::from_secs(cfg.cache_ttl_secs)),
            cfg,
        }
    }

    /// Execute AI_VERIFY opcode for canonical input. Returns deterministic AiVerifyResult on success.
    pub fn execute(&self, input: &AiVerifyInput) -> Result<AiVerifyResult, AiError> {
        // 1) Basic validation
        if input.model_id.is_empty() {
            return Err(AiError::InvalidPayload("missing model_id".into()));
        }

        // 2) Check cache (deterministic)
        if self.cfg.allow_cache {
            if let Some(cached) = self.cache.get(input) {
                return Ok(cached);
            }
        }

        // 3) Call model backend within budget
        let start = Instant::now();
        let model_output = self
            .backend
            .infer(input, self.cfg.budget_ms)
            .map_err(|e| AiError::ModelBackend(format!("{:?}", e)))?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        if elapsed_ms > self.cfg.budget_ms {
            // Resource budget exceeded: treat as failure to prevent abuse
            return Err(AiError::BudgetExceeded);
        }

        // 4) Normalize score and decide (deterministic)
        let score = Self::normalize_score(model_output.score);
        let decision = score >= self.cfg.required_score_threshold;

        // 5) Create a deterministic proof_hash: sha256(input_json || model_id || score || label)
        let proof_hash = {
            let mut hasher = Sha256::new();
            let canonical = serde_json::to_string(input).map_err(|e| AiError::Internal(e.to_string()))?;
            hasher.update(canonical.as_bytes());
            hasher.update(b"||");
            hasher.update(input.model_id.as_bytes());
            hasher.update(b"||");
            hasher.update(format!("{:.8}", score).as_bytes());
            if let Some(ref l) = model_output.label {
                hasher.update(b"||");
                hasher.update(l.as_bytes());
            }
            let digest = hasher.finalize();
            general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };

        let result = AiVerifyResult {
            model_id: input.model_id.clone(),
            decision,
            score,
            label: model_output.label.clone(),
            timestamp_utc: OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            proof_hash,
        };

        // 6) Cache result (deterministic)
        if self.cfg.allow_cache {
            self.cache.insert(input, result.clone());
        }

        // 7) Reputation hook (best-effort, non-critical)
        // Callers must ensure reputation hooks don't affect consensus; they should be off-chain or audited separately.
        let subject = format!("model:{}", input.model_id);
        self.reputation.record_verification(&subject, decision, score);

        Ok(result)
    }

    fn normalize_score(raw: f64) -> f64 {
        // clamp to [0,1] and round to 8 decimal deterministic precision
        let clamped = if raw.is_nan() {
            0.0
        } else if raw < 0.0 {
            0.0
        } else if raw > 1.0 {
            1.0
        } else {
            raw
        };
        // deterministic rounding:
        (clamped * 1e8).round() / 1e8
    }
}

// ----- Opcode enum & executor glue -----
#[derive(Clone, Debug)]
pub enum AiOpcode {
    /// AI_VERIFY: input is AiVerifyInput
    AiVerify(AiVerifyInput),
}

pub struct OpcodeExecutor {
    verifier: Arc<AiVerifier>,
}

impl OpcodeExecutor {
    pub fn new(verifier: Arc<AiVerifier>) -> Self {
        Self { verifier }
    }

    /// Execute the opcode and return serialized AiVerifyResult as JSON on success.
    /// This function is intentionally simple: the VM/host will control how the return is marshalled.
    pub fn execute(&self, op: AiOpcode) -> Result<String, AiError> {
        match op {
            AiOpcode::AiVerify(input) => {
                let res = self.verifier.execute(&input)?;
                serde_json::to_string(&res).map_err(|e| AiError::Internal(e.to_string()))
            }
        }
    }
}

// ----- Example integration / factory helpers -----
// Create a production-ready verifier wiring (replace backend with real implementation)
pub fn make_default_verifier() -> Arc<AiVerifier> {
    // stub backend + noop reputation; in production plug real implementations
    let backend: Arc<dyn ModelBackend> = Arc::new(InMemoryModelBackend::new());
    let rep: Arc<dyn ReputationHook> = Arc::new(NoopReputation {});
    let cfg = AiVerifierConfig {
        budget_ms: 200,
        cache_ttl_secs: 60,
        required_score_threshold: 0.75,
        allow_cache: true,
    };
    Arc::new(AiVerifier::new(backend, rep, cfg))
}

// ----- Test helpers (simple smoke test) -----
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inmemory_backend_deterministic() {
        let backend = InMemoryModelBackend::new();
        let input = AiVerifyInput {
            payload: serde_json::json!({"text":"hello"}),
            model_id: "test-v1".into(),
            params: None,
        };
        let a = backend.infer(&input, 100).unwrap();
        let b = backend.infer(&input, 100).unwrap();
        assert_eq!(a.score, b.score);
        assert_eq!(a.label, b.label);
    }

    #[test]
    fn test_verifier_flow() {
        let verifier = make_default_verifier();
        let input = AiVerifyInput {
            payload: serde_json::json!({"user_id": "alice", "action": "transfer", "amount": 100}),
            model_id: "fraud-model-v1".into(),
            params: Some(serde_json::json!({"threshold": 0.7})),
        };
        let res = verifier.execute(&input).expect("verifier execute failed");
        // deterministic fields exist
        assert_eq!(res.model_id, "fraud-model-v1");
        assert!(res.score >= 0.0 && res.score <= 1.0);
        assert!(!res.proof_hash.is_empty());
    }

    #[test]
    fn test_cache_hit() {
        let verifier = make_default_verifier();
        let input = AiVerifyInput {
            payload: serde_json::json!({"key":"value"}),
            model_id: "cached-model".into(),
            params: None,
        };
        let first = verifier.execute(&input).unwrap();
        // second should hit cache and return same proof_hash
        let second = verifier.execute(&input).unwrap();
        assert_eq!(first.proof_hash, second.proof_hash);
    }
}
