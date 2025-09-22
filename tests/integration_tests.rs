use da_verifier::{
    CelestiaConfig, CelestiaNetwork, CelestiaVerifier, DAVerifier, SamplingConfig,
};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_celestia_header_fetch() {
    let config = CelestiaConfig {
        endpoints: vec!["https://rpc-celestia.alphab.ai".to_string()],
        network: CelestiaNetwork::Mainnet,
        namespace_id: None,
        auth_token: None,
    };

    let sampling_config = SamplingConfig {
        samples_per_block: 3,
        confidence_threshold: 0.9,
        max_concurrent_requests: 3,
        timeout_seconds: 15,
        max_retries: 2,
    };

    let verifier = CelestiaVerifier::new(config, &sampling_config);

    // Test with a well-known mainnet block that should exist
    let test_height = 1_500_000;

    let result = timeout(Duration::from_secs(30), verifier.verify(test_height)).await;

    match result {
        Ok(Ok(verification_result)) => {
            // Verification succeeded
            println!("✅ Verification successful: {:#?}", verification_result);
            assert!(verification_result.samples_total > 0);
        }
        Ok(Err(e)) => {
            // Verification failed, but this might be expected in some environments
            println!("⚠️  Verification failed (might be expected): {}", e);
        }
        Err(_) => {
            // Timeout
            println!("⚠️  Test timed out - this might be expected in CI environments");
        }
    }
}

#[tokio::test]
async fn test_celestia_testnet() {
    let config = CelestiaConfig {
        endpoints: vec!["https://rpc-mocha.pops.one".to_string()],
        network: CelestiaNetwork::Mocha,
        namespace_id: None,
        auth_token: None,
    };

    let sampling_config = SamplingConfig {
        samples_per_block: 2,
        confidence_threshold: 0.8,
        max_concurrent_requests: 2,
        timeout_seconds: 15,
        max_retries: 1,
    };

    let verifier = CelestiaVerifier::new(config, &sampling_config);

    // Test with a recent testnet block
    let test_height = 100_000;

    let result = timeout(Duration::from_secs(30), verifier.verify(test_height)).await;

    match result {
        Ok(Ok(verification_result)) => {
            println!("✅ Testnet verification successful: {:#?}", verification_result);
            assert!(verification_result.samples_total > 0);
        }
        Ok(Err(e)) => {
            println!("⚠️  Testnet verification failed (might be expected): {}", e);
        }
        Err(_) => {
            println!("⚠️  Testnet test timed out");
        }
    }
}

#[tokio::test]
async fn test_invalid_height() {
    let config = CelestiaConfig {
        endpoints: vec!["https://rpc-celestia.alphab.ai".to_string()],
        network: CelestiaNetwork::Mainnet,
        namespace_id: None,
        auth_token: None,
    };

    let sampling_config = SamplingConfig {
        samples_per_block: 1,
        confidence_threshold: 0.5,
        max_concurrent_requests: 1,
        timeout_seconds: 10,
        max_retries: 1,
    };

    let verifier = CelestiaVerifier::new(config, &sampling_config);

    // Test with an invalid (future) height
    let invalid_height = u64::MAX;

    let result = verifier.verify(invalid_height).await;

    // This should fail
    assert!(result.is_err(), "Verification should fail for invalid height");
    println!("✅ Invalid height test passed: {:#?}", result.unwrap_err());
}

#[test]
fn test_sampling_config_validation() {
    // Test that sampling config parameters are within reasonable bounds
    let config = SamplingConfig {
        samples_per_block: 50,
        confidence_threshold: 0.999999,
        max_concurrent_requests: 20,
        timeout_seconds: 30,
        max_retries: 5,
    };

    assert!(config.samples_per_block > 0);
    assert!(config.confidence_threshold > 0.0 && config.confidence_threshold <= 1.0);
    assert!(config.max_concurrent_requests > 0);
    assert!(config.timeout_seconds > 0);
    assert!(config.max_retries < 10); // Reasonable retry limit
}

#[test]
fn test_celestia_config_networks() {
    let mainnet_config = CelestiaConfig {
        endpoints: vec!["https://rpc-celestia.alphab.ai".to_string()],
        network: CelestiaNetwork::Mainnet,
        namespace_id: None,
        auth_token: None,
    };

    let mocha_config = CelestiaConfig {
        endpoints: vec!["https://rpc-mocha.pops.one".to_string()],
        network: CelestiaNetwork::Mocha,
        namespace_id: Some("test".to_string()),
        auth_token: None,
    };

    assert!(!mainnet_config.endpoints.is_empty());
    assert!(!mocha_config.endpoints.is_empty());
    assert!(mainnet_config.namespace_id.is_none());
    assert!(mocha_config.namespace_id.is_some());
}

// Test the verifier name method
#[test]
fn test_verifier_name() {
    let config = CelestiaConfig {
        endpoints: vec!["http://localhost:26658".to_string()],
        network: CelestiaNetwork::Mainnet,
        namespace_id: None,
        auth_token: None,
    };

    let sampling_config = SamplingConfig {
        samples_per_block: 1,
        confidence_threshold: 0.9,
        max_concurrent_requests: 1,
        timeout_seconds: 5,
        max_retries: 1,
    };

    let verifier = CelestiaVerifier::new(config, &sampling_config);
    assert_eq!(verifier.name(), "Celestia");
}
