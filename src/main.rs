use clap::{Parser, Subcommand};
use da_verifier::{
    CelestiaConfig, CelestiaNetwork, CelestiaVerifier, DAConfig, DAVerifier, SamplingConfig,
};
use std::time::Instant;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "da_verifier")]
#[command(about = "A production-ready Data Availability verifier for multiple DA layers")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Set logging level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Number of samples per block
    #[arg(short, long, default_value_t = 30)]
    samples: usize,

    /// Confidence threshold (0.0 to 1.0)
    #[arg(short, long, default_value_t = 0.999999)]
    confidence: f64,

    /// Request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify data availability for Celestia
    Celestia {
        /// Block height to verify
        height: u64,

        /// Celestia network to use
        #[arg(short, long, default_value = "mainnet")]
        network: String,

        /// Custom RPC endpoint
        #[arg(short, long)]
        endpoint: Option<String>,

        /// Namespace ID (hex string)
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Verify multiple consecutive blocks
    Range {
        /// Starting block height
        start: u64,

        /// Ending block height
        end: u64,

        /// DA layer to use
        #[arg(short, long, default_value = "celestia")]
        layer: String,

        /// Custom RPC endpoint
        #[arg(short, long)]
        endpoint: Option<String>,
    },
    /// Test connection to DA layer endpoints
    Test {
        /// DA layer to test
        #[arg(short, long, default_value = "celestia")]
        layer: String,

        /// Custom RPC endpoint
        #[arg(short, long)]
        endpoint: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting DA Verifier v0.1.0");

    match cli.command {
        Commands::Celestia {
            height,
            network,
            endpoint,
            namespace,
        } => {
            let network = match network.to_lowercase().as_str() {
                "mainnet" => CelestiaNetwork::Mainnet,
                "mocha" => CelestiaNetwork::Mocha,
                "arabica" => CelestiaNetwork::Arabica,
                _ => {
                    eprintln!(
                        "Invalid network: {}. Use 'mainnet', 'mocha', or 'arabica'",
                        network
                    );
                    std::process::exit(1);
                }
            };

            let endpoints = if let Some(endpoint) = endpoint {
                vec![endpoint]
            } else {
                // Use default endpoints from config
                let default_config = DAConfig::default();
                default_config.celestia.unwrap().endpoints
            };

            let auth_token = std::env::var("CELESTIA_NODE_AUTH_TOKEN").ok();

            let config = CelestiaConfig {
                endpoints,
                network,
                namespace_id: namespace,
                auth_token,
            };

            let sampling_config = SamplingConfig {
                samples_per_block: cli.samples,
                confidence_threshold: cli.confidence,
                max_concurrent_requests: 10,
                timeout_seconds: cli.timeout,
                max_retries: 3,
            };

            let verifier = CelestiaVerifier::new(config, &sampling_config);

            info!(
                "Verifying Celestia block {} with {} samples",
                height, cli.samples
            );
            let start = Instant::now();

            match verifier.verify(height).await {
                Ok(result) => {
                    let duration = start.elapsed();

                    println!("\n📊 Verification Results for Celestia Block {}", height);
                    println!("═══════════════════════════════════════════════");
                    println!(
                        "✅ Data Available: {}",
                        if result.available { "YES" } else { "NO" }
                    );
                    println!(
                        "🎯 Confidence: {:.6} ({:.4}%)",
                        result.confidence,
                        result.confidence * 100.0
                    );
                    println!(
                        "📈 Samples: {}/{} successful",
                        result.samples_verified, result.samples_total
                    );
                    println!("⏱️  Latency: {}ms", result.latency_ms);
                    println!("🕐 Total Duration: {:?}", duration);

                    if !result.available {
                        warn!("⚠️  Data may not be available - confidence below threshold");
                    }
                }
                Err(e) => {
                    eprintln!("❌ Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Range {
            start,
            end,
            layer,
            endpoint: _,
        } => {
            if layer != "celestia" {
                eprintln!("Only Celestia is currently supported");
                std::process::exit(1);
            }

            if start > end {
                eprintln!("Start height cannot be greater than end height");
                std::process::exit(1);
            }

            // Use default configuration
            let default_config = DAConfig::default();
            let mut config = default_config.celestia.unwrap();
            if config.auth_token.is_none() {
                config.auth_token = std::env::var("CELESTIA_NODE_AUTH_TOKEN").ok();
            }

            let sampling_config = SamplingConfig {
                samples_per_block: cli.samples,
                confidence_threshold: cli.confidence,
                max_concurrent_requests: 10,
                timeout_seconds: cli.timeout,
                max_retries: 3,
            };

            let verifier = CelestiaVerifier::new(config, &sampling_config);

            println!(
                "\n🔍 Verifying Celestia blocks {} to {} ({} blocks)",
                start,
                end,
                end - start + 1
            );
            println!("═══════════════════════════════════════════════");

            let mut total_available = 0;
            let mut total_blocks = 0;
            let verification_start = Instant::now();

            for height in start..=end {
                total_blocks += 1;

                match verifier.verify(height).await {
                    Ok(result) => {
                        if result.available {
                            total_available += 1;
                        }

                        let status = if result.available { "✅" } else { "❌" };
                        println!(
                            "{} Block {}: {:.4}% confidence, {}/{} samples, {}ms",
                            status,
                            height,
                            result.confidence * 100.0,
                            result.samples_verified,
                            result.samples_total,
                            result.latency_ms
                        );
                    }
                    Err(e) => {
                        println!("❌ Block {}: Failed - {}", height, e);
                    }
                }
            }

            let total_duration = verification_start.elapsed();
            println!("\n📊 Range Verification Summary");
            println!("═══════════════════════════════════════════════");
            println!(
                "📈 Available blocks: {}/{} ({:.1}%)",
                total_available,
                total_blocks,
                (total_available as f64 / total_blocks as f64) * 100.0
            );
            println!("🕐 Total time: {:?}", total_duration);
            println!("⚡ Average per block: {:?}", total_duration / total_blocks);
        }
        Commands::Test { layer, endpoint } => {
            if layer != "celestia" {
                eprintln!("Only Celestia is currently supported");
                std::process::exit(1);
            }

            let endpoints = if let Some(endpoint) = endpoint {
                vec![endpoint]
            } else {
                // Use default endpoints from config
                let default_config = DAConfig::default();
                default_config.celestia.unwrap().endpoints
            };

            let config = CelestiaConfig {
                endpoints,
                network: CelestiaNetwork::Mainnet,
                namespace_id: None,
                auth_token: std::env::var("CELESTIA_NODE_AUTH_TOKEN").ok(),
            };

            let sampling_config = SamplingConfig {
                samples_per_block: 5, // Small number for testing
                confidence_threshold: 0.9,
                max_concurrent_requests: 3,
                timeout_seconds: cli.timeout,
                max_retries: 1,
            };

            let verifier = CelestiaVerifier::new(config, &sampling_config);

            println!("🧪 Testing connection to Celestia endpoints...");

            // Test with a recent block height
            let test_height = 2_000_000;

            match verifier.verify(test_height).await {
                Ok(result) => {
                    println!("✅ Connection successful!");
                    println!(
                        "📊 Test verification: {:.4}% confidence, {}/{} samples",
                        result.confidence * 100.0,
                        result.samples_verified,
                        result.samples_total
                    );
                }
                Err(e) => {
                    eprintln!("❌ Connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
