use attestation_verification::{
    DefaultCertificateFetcher, ErrorCode, ReportVerifier, ValidateError,
};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::{path::PathBuf, process::exit, sync::Arc};
use tracing::level_filters::LevelFilter;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    Validate(ValidateArgs),
}

#[derive(Args)]
struct ValidateArgs {
    report_hex: String,

    #[clap(short, long, default_value = default_cert_cache_path().into_os_string())]
    cert_cache: PathBuf,
}

fn default_cache_path() -> PathBuf {
    std::env::temp_dir().join("amd-verifier-cache")
}

fn default_cert_cache_path() -> PathBuf {
    default_cache_path().join("certs")
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum ValidateResult {
    Success {
        chip_id: String,
    },
    Failure {
        error_code: ErrorCode,
        message: String,
    },
}

async fn validate(args: ValidateArgs) -> Result<ValidateResult, ValidateError> {
    let fetcher = DefaultCertificateFetcher::new(args.cert_cache)
        .map_err(ValidateError::CertCacheDirectories)?;
    let verifier = ReportVerifier::new(Arc::new(fetcher));
    let report_bytes = match hex::decode(&args.report_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(ValidateResult::Failure {
                error_code: ErrorCode::InvalidReport,
                message: format!("Invalid Hex string: {}", e),
            });
        }
    };

    let report = match AttestationReport::from_bytes(&report_bytes) {
        Ok(report) => report,
        Err(e) => {
            return Ok(ValidateResult::Failure {
                error_code: ErrorCode::InvalidReport,
                message: format!("Invalid Report format: {}", e),
            });
        }
    };
    verifier.verify_report(&report).await?;

    Ok(ValidateResult::Success {
        chip_id: hex::encode(report.chip_id),
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let default_log_level = match cli.verbose {
        true => LevelFilter::INFO,
        false => LevelFilter::ERROR,
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::filter::EnvFilter::builder()
                .with_default_directive(default_log_level.into())
                .from_env_lossy(),
        )
        .init();

    match cli.command {
        Command::Validate(args) => {
            let (exit_code, result) = match validate(args).await {
                Ok(res) => (0, res),
                Err(e) => {
                    let message = e.to_string();
                    (
                        1,
                        ValidateResult::Failure {
                            error_code: e.into(),
                            message,
                        },
                    )
                }
            };
            println!(
                "{}",
                serde_json::to_string(&result).expect("failed to serialize")
            );
            exit(exit_code);
        }
    }
}
