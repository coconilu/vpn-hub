use std::{path::PathBuf, process::ExitCode, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::time::MissedTickBehavior;
use vpn_hub_core::{GuardianConfig, GuardianStore, HealthStatus, ProbeResult, probe_outlet};

#[derive(Debug, Parser)]
#[command(name = "vpn-hub", version, about = "VPN Hub local outlet guardian")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run one health-check cycle and persist sanitized results.
    Check {
        #[arg(short, long, default_value = "config/development.toml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Monitor outlets until Ctrl+C or an optional cycle limit.
    Monitor {
        #[arg(short, long, default_value = "config/development.toml")]
        config: PathBuf,
        #[arg(long)]
        cycles: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Print aggregate health history from an existing database.
    Summary {
        #[arg(short, long, default_value = "data/guardian-dev.db")]
        database: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Check { config, json } => {
            let config = GuardianConfig::load_static(&config)
                .with_context(|| format!("loading {}", config.display()))?;
            let mut store = GuardianStore::open(&config.database_path)?;
            let results = run_cycle(&config, &mut store).await?;
            print_results(&results, json)?;
            Ok(exit_code_for(&results))
        }
        Command::Monitor {
            config,
            cycles,
            json,
        } => monitor(&config, cycles, json).await,
        Command::Summary { database, json } => {
            let store = GuardianStore::open(database)?;
            let summaries = store.summaries()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summaries)?);
            } else {
                println!(
                    "{:<18} {:<11} {:>8} {:>9} {:>12}",
                    "OUTLET", "STATUS", "SAMPLES", "AVAIL %", "AVG LATENCY"
                );
                for item in summaries {
                    let latency = item
                        .average_latency_ms
                        .map_or_else(|| "-".into(), |value| format!("{value:.0} ms"));
                    println!(
                        "{:<18} {:<11} {:>8} {:>8.2} {:>12}",
                        item.outlet_id,
                        item.last_status,
                        item.samples,
                        item.availability_percent,
                        latency
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn monitor(path: &PathBuf, cycles: Option<u64>, json: bool) -> Result<ExitCode> {
    let config =
        GuardianConfig::load_static(path).with_context(|| format!("loading {}", path.display()))?;
    let mut store = GuardianStore::open(&config.database_path)?;
    let mut ticker = tokio::time::interval(Duration::from_secs(config.monitor.interval_seconds));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut completed = 0_u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let results = run_cycle(&config, &mut store).await?;
                print_results(&results, json)?;
                completed += 1;
                if cycles.is_some_and(|limit| completed >= limit) {
                    return Ok(exit_code_for(&results));
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for Ctrl+C")?;
                return Ok(ExitCode::SUCCESS);
            }
        }
    }
}

async fn run_cycle(config: &GuardianConfig, store: &mut GuardianStore) -> Result<Vec<ProbeResult>> {
    let mut results = Vec::new();
    for outlet in config.outlets.iter().filter(|outlet| outlet.enabled) {
        let result = probe_outlet(outlet, &config.monitor).await;
        if let Some(event) = store.record_probe(
            outlet,
            &result,
            config.monitor.failure_threshold,
            config.monitor.recovery_threshold,
        )? {
            eprintln!(
                "state-change outlet={} {}->{} reason={}",
                event.outlet_id, event.from_status, event.to_status, event.reason
            );
        }
        results.push(result);
    }
    Ok(results)
}

fn print_results(results: &[ProbeResult], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(results)?);
        return Ok(());
    }
    println!(
        "{:<18} {:<7} {:<11} {:>6} {:>10} {:<24}",
        "OUTLET", "PORT", "STATUS", "HTTP", "LATENCY", "ERROR"
    );
    for result in results {
        let latency = result
            .latency_ms
            .map_or_else(|| "-".into(), |value| format!("{value} ms"));
        println!(
            "{:<18} {:<7} {:<11} {:>6} {:>10} {:<24}",
            result.outlet_id,
            if result.port_reachable {
                "open"
            } else {
                "closed"
            },
            result.status,
            result
                .http_status
                .map_or_else(|| "-".into(), |value| value.to_string()),
            latency,
            result.error_code.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn exit_code_for(results: &[ProbeResult]) -> ExitCode {
    if results
        .iter()
        .any(|result| result.status == HealthStatus::Down)
    {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
