use crate::types::*;
use async_trait::async_trait;
use std::time::Instant;
use tracing::{error, info, warn};

#[async_trait]
pub trait DAVerifier: Send + Sync {
    async fn verify(&self, height: u64) -> Result<VerificationResult, DAError>;
    fn name(&self) -> &str;
}

pub struct VerificationEngine {
    verifiers: Vec<Box<dyn DAVerifier>>,
}

impl VerificationEngine {
    pub fn new(&self) -> Self {
        Self {
            verifiers: Vec::new(),
        }
    }

    pub fn add_verifier(&mut self, verifier: Box<dyn DAVerifier>) {
        self.verifiers.push(verifier);
    }

    pub async fn verify_all(&self, height: u64) -> Vec<(String, VerificationResult)> {
        let mut results = Vec::new();

        for verifier in &self.verifiers {
            let start = Instant::now();
            match verifier.verify(height).await {
                Ok(result) => {
                    info!(
                        "{}: Available={}, Confidence={:.6}, Samples={}/{}",
                        verifier.name(),
                        result.available,
                        result.confidence,
                        result.samples_verified,
                        result.samples_total
                    );
                    results.push((verifier.name().to_string(), result));
                }
                Err(e) => {
                    error!("{} verification failed: {}", verifier.name(), e);
                    results.push((
                        verifier.name().to_string(),
                        VerificationResult {
                            available: false,
                            confidence: 0.0,
                            samples_verified: 0,
                            samples_total: 0,
                            latency_ms: start.elapsed().as_millis() as u64,
                        },
                    ));
                }
            }
        }
        results
    }
}
