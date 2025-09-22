use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Represents a coordinate in a 2D data matrix
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coordinate {
    pub row: u32,
    pub col: u32,
}

/// Generic sample data with proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub coord: Coordinate,
    pub data: Vec<u8>,
    pub proof: Proof,
}

/// Different proof types for different DA layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proof {
    Merkle(MerkleProof),
    KZG(KZGProof),
    Kate(KateProof),
    Certificate(CertificateProof),
}

/// Merkle proof (used by Celestia)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub branch: Vec<[u8; 32]>,
    pub positions: Vec<bool>,
}

/// KZG proof (used by Ethereum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KZGProof {
    pub commitment: Vec<u8>,
    pub proof: Vec<u8>,
    pub y: Vec<u8>,
}

/// Kate proof (used by Avail)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KateProof {
    pub commitment: Vec<u8>,
    pub witness: Vec<u8>,
}

/// Certificate proof (used by EigenDA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProof {
    pub signatures: Vec<Vec<u8>>,
    pub stake_percentage: f64,
}

/// Generic block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub timestamp: u64,
    pub data_root: [u8; 32],
    pub matrix_size: u32,
    pub chunk_size: usize,
}

/// DA verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub available: bool,
    pub confidence: f64,
    pub samples_verified: usize,
    pub samples_total: usize,
    pub latency_ms: u64,
}

/// Errors that can occur during verification
#[derive(Debug, Error)]
pub enum DAError {
    #[error("Sample unavailable at ({row}, {col})")]
    SampleUnavailable { row: u32, col: u32 },
    
    #[error("Invalid proof")]
    InvalidProof,
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Insufficient samples: {got}/{needed}")]
    InsufficientSamples { got: usize, needed: usize },
}