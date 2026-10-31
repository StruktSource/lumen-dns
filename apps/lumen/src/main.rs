// SPDX-License-Identifier: Apache-2.0
//! Lumen DNS daemon. Startup is explicit and fails on unknown arguments.

use lumen_api::RunningApi;
use lumen_config::Config;
use lumen_core::RunningServer;
use lumen_store::{Command as ControlCommand, Store};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

const HELP: &str = "Lumen — private DNS, in your control.\n\nUsage: lumen --config FILE [--state FILE] [--check]\n       lumen --bind ADDRESS\n       lumen --version\n\n--config FILE   Load schema-versioned TOML configuration.\n--state FILE    Enable SQLite config/device storage and cross-platform control.\n--bind ADDRESS  Run UDP/TCP recursive DNS (loopback clients by default).\n--check         Validate config, filter sources, root hints, trust anchors, and TLS keys, then exit.\n--help          Show help.\n--version       Show version.\n\nEncrypted DNS and web listeners require explicit config and certificate/key files.";

enum Command {
    Help,
    Version,
    Run {
        path: Option<PathBuf>,
        state: Option<PathBuf>,
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
    let mut state = None;
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
            "--state" if state.is_none() => {
                state = Some(PathBuf::from(args.next().ok_or("--state needs a file")?));
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
    if state.is_some() && path.is_none() {
        return Err("--state requires --config".into());
    }
    Ok(Command::Run {
        path,
        state,
        bind,
        check,
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    match arguments(std::env::args().skip(1)).map_err(io::Error::other)? {
        Command::Help => println!("{HELP}"),
        Command::Version => println!("Lumen {}", env!("CARGO_PKG_VERSION")),
        Command::Run {
            path,
            state,
            bind,
            check,
        } => {
            let mut config = if let Some(path) = &path {
                Config::load(path).map_err(io::Error::other)?
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
                RunningServer::check(&config).await?;
                RunningApi::check(&config.management)?;
                println!("Lumen configuration valid");
                return Ok(());
            }
            if state.is_none() && config.management.listen.is_some() {
                return Err(io::Error::other(
                    "management API requires managed mode with --state",
                ));
            }
            if let (Some(config_path), Some(state_path)) = (path.as_deref(), state.as_deref()) {
                return run_managed(config_path, state_path).await;
            }
            let mut server = RunningServer::start(config).await?;
            print_endpoints(&server);
            let result = tokio::select! { result = server.wait() => result, result = shutdown_signal() => result };
            server.shutdown().await;
            result?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep managed DNS/API rollback in one state machine.
async fn run_managed(config_path: &Path, state_path: &Path) -> io::Result<()> {
    let mut store = Store::open(state_path).map_err(io::Error::other)?;
    if store.config().map_err(io::Error::other)?.is_none() {
        let bytes = lumen_config::read_bounded(config_path, 65536).map_err(io::Error::other)?;
        let source =
            std::str::from_utf8(&bytes).map_err(|_| io::Error::other("config must be UTF-8"))?;
        store
            .set_config(
                source,
                config_path.parent().unwrap_or_else(|| Path::new(".")),
            )
            .map_err(io::Error::other)?;
    }
    let mut config = managed_config(&mut store, false)?;
    let mut server = RunningServer::start(config.clone()).await?;
    let mut api = match RunningApi::start(config.management.clone(), state_path).await {
        Ok(api) => api,
        Err(error) => {
            server.shutdown().await;
            return Err(error);
        }
    };
    store
        .set_status("running", None)
        .map_err(io::Error::other)?;
    print_endpoints(&server);
    print_api(api.as_ref());
    let mut controls = tokio::time::interval(Duration::from_millis(500));
    controls.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = server.wait() => {
                let message = result.as_ref().err().map(ToString::to_string);
                store.set_status("failed", message.as_deref()).map_err(io::Error::other)?;
                server.shutdown().await;
                shutdown_api(&mut api).await;
                return result;
            }
            result = wait_api(&mut api) => {
                let message = result.as_ref().err().map(ToString::to_string);
                store.set_status("failed", message.as_deref()).map_err(io::Error::other)?;
                server.shutdown().await;
                shutdown_api(&mut api).await;
                return result;
            }
            result = &mut shutdown => {
                result?;
                store.set_status("stopped", None).map_err(io::Error::other)?;
                server.shutdown().await;
                shutdown_api(&mut api).await;
                return Ok(());
            }
            _ = controls.tick() => {
                let Some((_id, command)) = store.next_command().map_err(io::Error::other)? else { continue };
                match command {
                    ControlCommand::FilterRefresh => {
                        record_control(&store, server.filter.refresh().await, "filter refreshed")?;
                    }
                    ControlCommand::FilterRollback => {
                        record_control(&store, server.filter.rollback().await, "filter rolled back")?;
                    }
                    ControlCommand::Reload | ControlCommand::ConfigReload(_) => {
                        let staged_revision = match command {
                            ControlCommand::ConfigReload(revision) => {
                                let current = store.staged_config().map_err(io::Error::other)?;
                                if current.as_ref().is_none_or(|config| config.revision != revision) {
                                    continue;
                                }
                                Some(revision)
                            }
                            _ => None,
                        };
                        let staged = staged_revision.is_some();
                        match managed_config(&mut store, staged) {
                            Ok(next) => {
                                if let Err(error) = RunningServer::check(&next).await {
                                    if let Some(revision) = staged_revision { store.discard_staged_config(revision).map_err(io::Error::other)?; }
                                    store.set_status("running", Some(&format!("reload rejected: {error}"))).map_err(io::Error::other)?;
                                    continue;
                                }
                                if let Err(error) = RunningApi::check(&next.management) {
                                    if let Some(revision) = staged_revision { store.discard_staged_config(revision).map_err(io::Error::other)?; }
                                    store.set_status("running", Some(&format!("reload rejected: {error}"))).map_err(io::Error::other)?;
                                    continue;
                                }
                                server.shutdown().await;
                                shutdown_api(&mut api).await;
                                match RunningServer::start(next.clone()).await {
                                    Ok(mut next_server) => {
                                        match RunningApi::start(next.management.clone(), state_path).await {
                                            Ok(next_api) => {
                                                server = next_server;
                                                api = next_api;
                                                config = next;
                                                if let Some(revision) = staged_revision { let _ = store.promote_staged_config(revision).map_err(io::Error::other)?; }
                                                store.set_status("running", None).map_err(io::Error::other)?;
                                                print_endpoints(&server);
                                                print_api(api.as_ref());
                                            }
                                            Err(error) => {
                                                next_server.shutdown().await;
                                                if let Some(revision) = staged_revision { store.discard_staged_config(revision).map_err(io::Error::other)?; }
                                                server = RunningServer::start(config.clone()).await.map_err(|rollback| io::Error::other(format!("API reload failed: {error}; DNS rollback failed: {rollback}")))?;
                                                api = RunningApi::start(config.management.clone(), state_path).await.map_err(|rollback| io::Error::other(format!("API reload failed: {error}; API rollback failed: {rollback}")))?;
                                                store.set_status("running", Some(&format!("reload failed; prior config restored: {error}"))).map_err(io::Error::other)?;
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        if let Some(revision) = staged_revision { store.discard_staged_config(revision).map_err(io::Error::other)?; }
                                        server = RunningServer::start(config.clone()).await.map_err(|rollback| {
                                            io::Error::other(format!("reload failed: {error}; rollback failed: {rollback}"))
                                        })?;
                                        api = RunningApi::start(config.management.clone(), state_path).await.map_err(|rollback| io::Error::other(format!("reload failed: {error}; API rollback failed: {rollback}")))?;
                                        store.set_status("running", Some(&format!("reload failed; prior config restored: {error}"))).map_err(io::Error::other)?;
                                    }
                                }
                            }
                            Err(error) => {
                                if let Some(revision) = staged_revision { store.discard_staged_config(revision).map_err(io::Error::other)?; }
                                store.set_status("running", Some(&format!("reload rejected: {error}"))).map_err(io::Error::other)?;
                            }
                        }
                    }
                    ControlCommand::Shutdown => {
                        store.set_status("stopped", None).map_err(io::Error::other)?;
                        server.shutdown().await;
                        shutdown_api(&mut api).await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn wait_api(api: &mut Option<RunningApi>) -> io::Result<()> {
    match api {
        Some(api) => api.wait().await,
        None => std::future::pending().await,
    }
}

async fn shutdown_api(api: &mut Option<RunningApi>) {
    if let Some(api) = api {
        api.shutdown().await;
    }
}

fn print_api(api: Option<&RunningApi>) {
    if let Some(api) = api {
        println!("Lumen management API listening on {}", api.address);
    }
}

fn managed_config(store: &mut Store, staged: bool) -> io::Result<Config> {
    let stored = if staged {
        store.staged_config()
    } else {
        store.config()
    }
    .map_err(io::Error::other)?
    .ok_or_else(|| {
        io::Error::other(if staged {
            "state has no staged config"
        } else {
            "state has no active config"
        })
    })?;
    let mut config =
        Config::parse(&stored.source, Path::new(&stored.base_dir)).map_err(io::Error::other)?;
    store
        .initialize_devices(&config.filtering.devices)
        .map_err(io::Error::other)?;
    config.filtering.devices = store.devices().map_err(io::Error::other)?;
    config.validate().map_err(io::Error::other)?;
    Ok(config)
}

fn record_control(store: &Store, result: Result<(), String>, success: &str) -> io::Result<()> {
    match result {
        Ok(()) => {
            eprintln!("{success}");
            store.set_status("running", None).map_err(io::Error::other)
        }
        Err(error) => store
            .set_status("running", Some(&error))
            .map_err(io::Error::other),
    }
}

fn print_endpoints(server: &RunningServer) {
    for (protocol, address) in &server.endpoints {
        println!("Lumen {protocol:?} listening on {address}");
    }
    for (tls, address) in &server.web_endpoints {
        let protocol = if *tls { "HTTPS" } else { "HTTP" };
        println!("Lumen web {protocol} listening on {address}");
    }
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
