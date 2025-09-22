use std::{path::PathBuf, sync::Arc, thread};

use anyhow::{Result, bail};
use clap::{Parser, builder::PossibleValuesParser};
use log::{LevelFilter, error};
use once_cell::sync::OnceCell;
use tokio::runtime;

mod config;
mod context;
mod http;
mod logger;
mod proxy_protocol;
mod reader;
mod tcp;
mod tls;
mod zc;

use crate::{config::Config, logger::Logger};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["error", "warn", "info", "debug", "trace"]),
        default_value = "info",
        help = "Log level",
    )]
    pub(crate) log_level: String,
    #[arg(
        short,
        long,
        default_value = "sniproxy.yaml",
        help = "Path to the configuration file"
    )]
    config: PathBuf,
}

fn main() -> Result<()> {
    // Start by parsing the cli arguments.
    let args = Args::parse();

    // Set the log level.
    let log_level = match args.log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        x => bail!("Invalid log_level: {}", x),
    };
    Logger::init(log_level)?;

    // Parse the configuration file.
    let config = Arc::new(Config::from_file(args.config)?);

    let mut threads = Vec::new();

    // Start the TLS listener and handle incoming connections.
    let _config = Arc::clone(&config);
    let bind = config.bind_https;
    threads.push((
        "HTTPS",
        thread::spawn(move || {
            if let Err(e) = tcp::listen_and_proxy(_config, bind, tcp::tls::handle_stream) {
                error!("HTTPS listener returned: {e}");
            }
        }),
    ));

    // Start the HTTP listener and handle incoming connections, if needed.
    if config.need_http() {
        let _config = Arc::clone(&config);
        let bind = config.bind_http;
        threads.push((
            "HTTP",
            thread::spawn(move || {
                if let Err(e) = tcp::listen_and_proxy(_config, bind, tcp::http::handle_stream) {
                    error!("HTTP listener returned: {e}");
                }
            }),
        ));
    }

    // Wait for threads to join.
    threads.drain(..).for_each(|(name, t)| {
        if t.join().is_err() {
            error!("{name} server thread returned unexpectedly");
        }
    });

    Ok(())
}

static RUNTIME: OnceCell<runtime::Runtime> = OnceCell::new();

#[macro_export]
macro_rules! runtime {
    () => {
        RUNTIME.get_or_try_init(|| runtime::Builder::new_multi_thread().enable_io().build())
    };
}
