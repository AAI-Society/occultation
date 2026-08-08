use anyhow::Result;
use clap::{Parser, Subcommand};
use occultation::bench::{run_bench, BenchOptions};
use occultation::modelled::MODELLED_WARNING;
use occultation::report::Format;
use std::process::ExitCode;

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
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
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
            ExitCode::from(2)
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
            let table = costs.table();
            match format {
                Format::Table => println!("{}", table.render()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&table.to_json())?),
            }
            let _ = composed; // wired in Task 8
            Ok(ExitCode::SUCCESS)
        }
    }
}
