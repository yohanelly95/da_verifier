use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAConfig {
    pub celestia: Option<CelestiaConfig>,
    pub ethereum: Option<EthereumConfig>,
    pub avail: Option<AvailConfig>,
    pub eigenda: Option<EigenDAConfig>,
    pub near: Option<NearConfig>,
    pub sampling: SamplingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    pub samples_per_block: usize,
    pub confidence_threshold: f64,
    pub max_concurrent_requests: usize,
    pub timeout_seconds: u64,
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaConfig {
    pub endpoints: Vec<String>,
    pub network: CelestiaNetwork,
    pub namespace_id: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CelestiaNetwork {
    Mainnet,
    Mocha,
    Arabica,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    pub beacon_endpoints: Vec<String>,
    pub execution_endpoints: Vec<String>,
    pub network: EthNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EthNetwork {
    Mainnet,
    Sepolia,
    Holesky,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailConfig {
    pub endpoints: Vec<String>,
    pub network: AvailNetwork,
    pub app_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AvailNetwork {
    Mainnet,
    Turing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EigenDAConfig {
    pub disperser_endpoint: String,
    pub network: EigenDANetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EigenDANetwork {
    Mainnet,
    Holesky,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearConfig {
    pub endpoints: Vec<String>,
    pub network: NearNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NearNetwork {
    Mainnet,
    Testnet,
}

impl Default for DAConfig {
    fn default() -> Self {
        Self {
            celestia: Some(CelestiaConfig {
                endpoints: vec![
                    "http://91.99.137.205:26658".to_string(),
                    "https://celestia-rpc.brightlystake.com/api".to_string(),
                    "https://celestia.rest.lava.build".to_string(),
                ],
                network: CelestiaNetwork::Mainnet,
                namespace_id: None,
                auth_token: None,
            }),
            ethereum: Some(EthereumConfig {
                beacon_endpoints: vec!["https://beacon-nd-mainnet.ethereum.org".to_string()],
                execution_endpoints: vec!["https://eth-mainnet.g.alchemy.com/v2/demo".to_string()],
                network: EthNetwork::Mainnet,
            }),
            avail: Some(AvailConfig {
                endpoints: vec!["https://mainnet-rpc.avail.so/".to_string()],
                network: AvailNetwork::Mainnet,
                app_id: 0,
            }),
            eigenda: Some(EigenDAConfig {
                disperser_endpoint: "disperser.eigenda.xyz:443".to_string(),
                network: EigenDANetwork::Mainnet,
            }),
            near: Some(NearConfig {
                endpoints: vec!["https://rpc.mainnet.near.org".to_string()],
                network: NearNetwork::Mainnet,
            }),
            sampling: SamplingConfig {
                samples_per_block: 30,
                confidence_threshold: 0.999999,
                max_concurrent_requests: 10,
                timeout_seconds: 5,
                max_retries: 3,
            },
        }
    }
}
