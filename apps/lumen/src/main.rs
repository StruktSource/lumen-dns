// SPDX-License-Identifier: Apache-2.0
//! Lumen DNS daemon. Startup is explicit and fails on unknown arguments.

use lumen_config::Config;
use lumen_core::RunningServer;
use std::{io, net::SocketAddr, path::PathBuf};

const HELP: &str = "Lumen — private DNS, in your control.\n\nUsage: lumen --config FILE [--check]\n       lumen --bind ADDRESS\n       lumen --version\n\n--config FILE   Load schema-versioned TOML configuration.\n--bind ADDRESS  Run UDP/TCP recursive DNS (loopback clients by default).\n--check         Validate config, root hints, trust anchors, and TLS keys, then exit.\n--help          Show help.\n--version       Show version.\n\nEncrypted listeners require explicit config and certificate/key files.";

enum Command {
    Help,
    Version,
    Run {
        path: Option<PathBuf>,
        bind: Option<SocketAddr>,
        check: bool,
    },
}

fn arguments(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter().peekable();
    if args.peek().is_none() {
        return Ok(Command::Help);
    }
    let mut path = None;
    let mut bind = None;
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h"
                if path.is_none() && bind.is_none() && !check && args.peek().is_none() =>
            {
                return Ok(Command::Help);
            }
            "--version" | "-V"
                if path.is_none() && bind.is_none() && !check && args.peek().is_none() =>
            {
                return Ok(Command::Version);
            }
            "--config" if path.is_none() => {
                path = Some(PathBuf::from(args.next().ok_or("--config needs a file")?));
            }
            "--bind" if bind.is_none() => {
                bind = Some(
                    args.next()
                        .ok_or("--bind needs an address")?
                        .parse()
                        .map_err(|_| "invalid --bind address")?,
                );
            }
            "--check" if !check => check = true,
            _ => return Err(format!("unknown or repeated argument: {arg}")),
        }
    }
    if path.is_some() && bind.is_some() {
        return Err("choose --config or --bind".into());
    }
    if path.is_none() && bind.is_none() {
        return Err("choose --config or --bind".into());
    }
    Ok(Command::Run { path, bind, check })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    match arguments(std::env::args().skip(1)).map_err(io::Error::other)? {
        Command::Help => println!("{HELP}"),
        Command::Version => println!("Lumen {}", env!("CARGO_PKG_VERSION")),
        Command::Run { path, bind, check } => {
            let mut config = if let Some(path) = path {
                Config::load(&path).map_err(io::Error::other)?
            } else {
                Config {
                    schema_version: 1,
                    ..Config::default()
                }
            };
            if let Some(bind) = bind {
                config.listen.udp = vec![bind];
                config.listen.tcp = vec![bind];
            }
            if check {
                RunningServer::check(&config)?;
                println!("Lumen configuration valid");
                return Ok(());
            }
            let mut server = RunningServer::start(config)?;
            for (protocol, address) in &server.endpoints {
                println!("Lumen {protocol:?} listening on {address}");
            }
            let result = tokio::select! { result = server.wait() => result, result = shutdown_signal() => result };
            server.shutdown().await;
            result?;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Command, String> {
        arguments(args.iter().map(ToString::to_string))
    }
    #[test]
    fn rejects_missing_values_and_extra_args() {
        for args in [
            vec!["--bind"],
            vec!["--config"],
            vec!["--check"],
            vec!["--bind", "127.0.0.1:5353", "junk"],
            vec!["--config", "x", "--bind", "127.0.0.1:5353"],
            vec!["--version", "--bind", "127.0.0.1:5353"],
        ] {
            assert!(parse(&args).is_err());
        }
        assert!(matches!(
            parse(&["--bind", "127.0.0.1:5353"]),
            Ok(Command::Run { .. })
        ));
        assert!(matches!(
            parse(&["--config", "x", "--check"]),
            Ok(Command::Run { check: true, .. })
        ));
    }
}
