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
        measurement: String,
        host_data: String,
        report_data: String,
        policy: String,
        reported_tcb: String,
        id_key_digest: String,
    },
    Failure {
        error_code: ErrorCode,
        message: String,
    },
}

/// Serialize a TcbVersion as a stable 16-char lowercase hex string.
///
/// The byte layout depends on whether the report's TCB uses the legacy
/// (pre-FMC) or Turin (FMC-enabled) format. These two layouts mirror the
/// `sev` crate's internal `TcbVersion::to_legacy_bytes` and `to_turin_bytes`
/// functions — we reconstruct the on-wire 8-byte representation and reinterpret
/// as u64 (little-endian). This is necessary because `sev` 7.1.0 does not
/// expose a public "serialize back to u64" method.
///
/// If the `sev` crate ever changes how `AttestationReport::from_bytes` parses
/// the TCB, update this helper to match the new byte layout.
fn tcb_to_u64_hex(tcb: &sev::firmware::host::TcbVersion) -> String {
    let bytes = match tcb.fmc {
        None => [tcb.bootloader, tcb.tee, 0u8, 0u8, 0u8, 0u8, tcb.snp, tcb.microcode],
        Some(fmc) => [fmc, tcb.bootloader, tcb.tee, tcb.snp, 0u8, 0u8, 0u8, tcb.microcode],
    };
    format!("{:016x}", u64::from_le_bytes(bytes))
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
        measurement: hex::encode(report.measurement),
        host_data: hex::encode(report.host_data),
        report_data: hex::encode(report.report_data),
        policy: format!("{:016x}", report.policy.0),
        reported_tcb: tcb_to_u64_hex(&report.reported_tcb),
        id_key_digest: hex::encode(report.id_key_digest),
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
