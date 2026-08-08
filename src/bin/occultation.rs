use anyhow::Result;
use clap::{Parser, Subcommand};
use occultation::bench::{run_bench, BenchOptions};
use occultation::modelled::MODELLED_WARNING;
use occultation::report::Format;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "occultation",
    version,
    about = "Measure what verifiable unlinkability costs at agent action rates"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Primitive costs against the Ed25519 baseline
    Bench {
        /// Assess presentation AND verification against the 15 ms budget
        #[arg(long)]
        composed: bool,
        /// Timed iterations per primitive. Rejected at parse time if zero,
        /// so the failure is an exit-2 usage error rather than an error from
        /// deep inside the harness.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
        iters: u32,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value_t = 10)]
        attributes: usize,
        #[arg(long, default_value_t = 2)]
        disclose: usize,
        /// Run components that provide no security
        #[arg(long)]
        allow_modelled: bool,
        #[arg(long, default_value = "table")]
        format: Format,
    },
    /// Pre-computation pool under load
    Pool {
        /// Presentations per second during the burst
        #[arg(long)]
        burst: f64,
        #[arg(long, default_value = "10s")]
        duration: humantime::Duration,
        #[arg(long, default_value_t = 64)]
        capacity: usize,
        /// Cost of pre-computing one pool item; defaults to a measured presentation
        #[arg(long)]
        refill: Option<humantime::Duration>,
        /// Cost of finishing a presentation from a pool item; defaults to measured
        #[arg(long)]
        online: Option<humantime::Duration>,
        /// Exit 1 if the worst stall exceeds this
        #[arg(long)]
        max_stall: Option<humantime::Duration>,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value = "table")]
        format: Format,
    },
}

fn main() -> ExitCode {
    // `default_filter_or("warn")`, not `env_logger::init()`. The latter
    // defaults to `error` when RUST_LOG is unset, which would silently
    // discard every modelled-component warning — barrier 3 would hold in
    // the library and vanish at the binary.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    match run() {
        Ok(code) => code,
        // `{e}` not `{e:#}` — the library error types already interpolate
        // their own source, so the alternate formatter prints every cause
        // twice.
        Err(e) => {
            eprintln!("error: {e}");
            // Not a blanket 2: a modelled component requested without the
            // flag is exit 3, and downcasting is how anyhow lets the binary
            // recover the library's own classification.
            let code = e
                .downcast_ref::<occultation::bench::BenchError>()
                .map(|b| b.exit_code())
                .unwrap_or(2);
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Bench {
            composed,
            iters,
            seed,
            attributes,
            disclose,
            allow_modelled,
            format,
        } => {
            if allow_modelled {
                eprintln!("{MODELLED_WARNING}\n");
            }
            let opts = BenchOptions {
                iters,
                seed,
                attributes,
                disclose,
                allow_modelled,
            };
            let costs = run_bench(&opts)?;
            if composed {
                let report = occultation::bench::composed_report(&costs);
                match format {
                    Format::Table => println!("{}", report.render()),
                    Format::Json => {
                        println!("{}", serde_json::to_string_pretty(&report.to_json())?)
                    }
                }
            } else {
                let table = costs.table();
                match format {
                    Format::Table => println!("{}", table.render()),
                    Format::Json => println!("{}", serde_json::to_string_pretty(&table.to_json())?),
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Pool {
            burst,
            duration,
            capacity,
            refill,
            online,
            max_stall,
            seed,
            format,
        } => {
            // Defaults come from this host, not from a guess. Measuring costs
            // a second; inventing a refill cost would make the whole
            // simulation fiction. Stated on stderr so it never contaminates
            // machine-readable stdout, but every run says which of the two
            // costs below were measured and which were given.
            let refill_given = refill.is_some();
            let online_given = online.is_some();
            let (refill_cost, online_cost) = match (refill, online) {
                (Some(r), Some(o)) => (r.into(), o.into()),
                (r, o) => {
                    let costs = run_bench(&BenchOptions {
                        iters: 30,
                        seed,
                        ..Default::default()
                    })?;
                    (
                        r.map(Into::into).unwrap_or(costs.present.median),
                        o.map(Into::into).unwrap_or(costs.hash_to_scalar.median * 2),
                    )
                }
            };
            eprintln!(
                "refill cost   {} ({})\nonline cost   {} ({})\n",
                occultation::cost::fmt_ms(refill_cost),
                if refill_given {
                    "given"
                } else {
                    "measured on this host: one presentation's group work"
                },
                occultation::cost::fmt_ms(online_cost),
                if online_given {
                    "given"
                } else {
                    "measured on this host: 2x hash-to-scalar"
                },
            );
            let cfg = occultation::pool::BurstConfig {
                capacity,
                refill_cost,
                online_cost,
                burst_rate_hz: burst,
                duration: duration.into(),
                seed,
            };
            let report = occultation::pool::simulate_burst(&cfg)?;
            match format {
                Format::Table => println!("{}", report.render()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&report.to_json())?),
            }
            if let Some(limit) = max_stall {
                if report.stall_max > limit.into() {
                    eprintln!(
                        "VIOLATION: worst stall {:?} exceeds --max-stall {:?}",
                        report.stall_max,
                        Duration::from(limit)
                    );
                    return Ok(ExitCode::from(1));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
