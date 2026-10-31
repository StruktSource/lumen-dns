// SPDX-License-Identifier: Apache-2.0
//! Cross-platform local control through Lumen's versioned `SQLite` state.

use lumen_filter::config::Device;
use lumen_store::{Command as ControlCommand, Role, Store, password};
use std::{
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const HELP: &str = "Usage:
  lumenctl config validate --config FILE
  lumenctl config apply --config FILE --state FILE
  lumenctl config show --state FILE
  lumenctl reload|status|shutdown --state FILE
  lumenctl filter refresh|rollback --state FILE
  lumenctl filter-explain --config FILE --client IP --domain NAME [--at UNIX_SECONDS]
  lumenctl device list --state FILE
  lumenctl device set --state FILE --id ID --address IP [--address IP] [--profile ID] [--group ID]
  lumenctl device remove --state FILE --id ID
  lumenctl user list --state FILE
  lumenctl user add --state FILE --name NAME [--role admin|user] --password stdin|generate
  lumenctl user reset-password --state FILE --name NAME --password stdin|generate
  lumenctl user reset-2fa --state FILE --name NAME

Console accounts: `--password stdin` reads one line from standard input, e.g.
  printf '%s' \"$PASSWORD\" | lumenctl user add --state state.db --name admin --role admin --password stdin
`--password generate` prints a random password the person must change at first sign-in.";

#[derive(Debug)]
enum Command {
    ConfigValidate {
        config: PathBuf,
    },
    ConfigApply {
        config: PathBuf,
        state: PathBuf,
    },
    ConfigShow {
        state: PathBuf,
    },
    Control {
        state: PathBuf,
        command: ControlCommand,
    },
    Status {
        state: PathBuf,
    },
    DeviceList {
        state: PathBuf,
    },
    DeviceSet {
        state: PathBuf,
        device: Device,
    },
    DeviceRemove {
        state: PathBuf,
        id: String,
    },
    Explain {
        config: PathBuf,
        client: IpAddr,
        domain: String,
        at: Option<u64>,
    },
    UserList {
        state: PathBuf,
    },
    UserAdd {
        state: PathBuf,
        name: String,
        role: Role,
        generate: bool,
    },
    User2faReset {
        state: PathBuf,
        name: String,
    },
    UserReset {
        state: PathBuf,
        name: String,
        generate: bool,
    },
}

fn arguments(args: impl IntoIterator<Item = String>) -> Result<Option<Command>, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        return Ok(None);
    }
    match args.as_slice() {
        [name, rest @ ..] if name == "config" => config_command(rest),
        [name, rest @ ..] if name == "device" => device_command(rest),
        [name, rest @ ..] if name == "user" => user_command(rest),
        [name, action, rest @ ..] if name == "filter" && action == "refresh" => {
            Ok(Some(Command::Control {
                state: one_path(rest, "--state")?,
                command: ControlCommand::FilterRefresh,
            }))
        }
        [name, action, rest @ ..] if name == "filter" && action == "rollback" => {
            Ok(Some(Command::Control {
                state: one_path(rest, "--state")?,
                command: ControlCommand::FilterRollback,
            }))
        }
        [name, rest @ ..] if name == "reload" => Ok(Some(Command::Control {
            state: one_path(rest, "--state")?,
            command: ControlCommand::Reload,
        })),
        [name, rest @ ..] if name == "shutdown" => Ok(Some(Command::Control {
            state: one_path(rest, "--state")?,
            command: ControlCommand::Shutdown,
        })),
        [name, rest @ ..] if name == "status" => Ok(Some(Command::Status {
            state: one_path(rest, "--state")?,
        })),
        [name, rest @ ..] if name == "filter-explain" => explain_command(rest),
        _ => Err(HELP.into()),
    }
}

fn config_command(args: &[String]) -> Result<Option<Command>, String> {
    match args {
        [action, rest @ ..] if action == "validate" => Ok(Some(Command::ConfigValidate {
            config: one_path(rest, "--config")?,
        })),
        [action, rest @ ..] if action == "show" => Ok(Some(Command::ConfigShow {
            state: one_path(rest, "--state")?,
        })),
        [action, rest @ ..] if action == "apply" => {
            let values = options(rest, &["--config", "--state"], &[])?;
            Ok(Some(Command::ConfigApply {
                config: PathBuf::from(required(&values, "--config")?),
                state: PathBuf::from(required(&values, "--state")?),
            }))
        }
        _ => Err(HELP.into()),
    }
}

fn device_command(args: &[String]) -> Result<Option<Command>, String> {
    match args {
        [action, rest @ ..] if action == "list" => Ok(Some(Command::DeviceList {
            state: one_path(rest, "--state")?,
        })),
        [action, rest @ ..] if action == "remove" => {
            let values = options(rest, &["--state", "--id"], &[])?;
            Ok(Some(Command::DeviceRemove {
                state: PathBuf::from(required(&values, "--state")?),
                id: required(&values, "--id")?.to_owned(),
            }))
        }
        [action, rest @ ..] if action == "set" => {
            let values = options(
                rest,
                &["--state", "--id", "--profile", "--group"],
                &["--address"],
            )?;
            let addresses = values
                .iter()
                .filter(|(key, _)| key == "--address")
                .map(|(_, value)| value.parse().map_err(|_| "invalid device IP".to_owned()))
                .collect::<Result<Vec<_>, _>>()?;
            if addresses.is_empty() {
                return Err("at least one --address is required".into());
            }
            let profile = optional(&values, "--profile").map(ToOwned::to_owned);
            let group = optional(&values, "--group").map(ToOwned::to_owned);
            if profile.is_none() && group.is_none() {
                return Err("choose --profile, --group, or both".into());
            }
            Ok(Some(Command::DeviceSet {
                state: PathBuf::from(required(&values, "--state")?),
                device: Device {
                    id: required(&values, "--id")?.to_owned(),
                    addresses,
                    profile,
                    group,
                },
            }))
        }
        _ => Err(HELP.into()),
    }
}

fn user_command(args: &[String]) -> Result<Option<Command>, String> {
    let generate = |values: &[(String, String)]| match required(values, "--password")? {
        "generate" => Ok(true),
        "stdin" => Ok(false),
        _ => Err("--password must be stdin or generate".to_owned()),
    };
    match args {
        [action, rest @ ..] if action == "list" => Ok(Some(Command::UserList {
            state: one_path(rest, "--state")?,
        })),
        [action, rest @ ..] if action == "add" => {
            let values = options(rest, &["--state", "--name", "--role", "--password"], &[])?;
            Ok(Some(Command::UserAdd {
                state: PathBuf::from(required(&values, "--state")?),
                name: required(&values, "--name")?.to_owned(),
                role: Role::parse(optional(&values, "--role").unwrap_or("user"))?,
                generate: generate(&values)?,
            }))
        }
        [action, rest @ ..] if action == "reset-2fa" => {
            let values = options(rest, &["--state", "--name"], &[])?;
            Ok(Some(Command::User2faReset {
                state: PathBuf::from(required(&values, "--state")?),
                name: required(&values, "--name")?.to_owned(),
            }))
        }
        [action, rest @ ..] if action == "reset-password" => {
            let values = options(rest, &["--state", "--name", "--password"], &[])?;
            Ok(Some(Command::UserReset {
                state: PathBuf::from(required(&values, "--state")?),
                name: required(&values, "--name")?.to_owned(),
                generate: generate(&values)?,
            }))
        }
        _ => Err(HELP.into()),
    }
}

/// A new password: generated, or one line from standard input.
fn new_password(generate: bool, name: &str) -> io::Result<String> {
    if generate {
        return password::random_hex(10).map_err(io::Error::other);
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let line = line.trim_end_matches(['\r', '\n']).to_owned();
    password::check_policy(&line, name).map_err(io::Error::other)?;
    Ok(line)
}

fn explain_command(args: &[String]) -> Result<Option<Command>, String> {
    let values = options(args, &["--config", "--client", "--domain", "--at"], &[])?;
    Ok(Some(Command::Explain {
        config: PathBuf::from(required(&values, "--config")?),
        client: required(&values, "--client")?
            .parse()
            .map_err(|_| "invalid client IP")?,
        domain: lumen_filter::rules::normalize(required(&values, "--domain")?)?,
        at: optional(&values, "--at")
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid Unix time")?,
    }))
}

fn options(
    args: &[String],
    allowed: &[&str],
    repeated: &[&str],
) -> Result<Vec<(String, String)>, String> {
    if !args.len().is_multiple_of(2) {
        return Err("missing option value".into());
    }
    let mut values = Vec::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str()) && !repeated.contains(&pair[0].as_str()) {
            return Err(format!("unknown option: {}", pair[0]));
        }
        if !repeated.contains(&pair[0].as_str()) && values.iter().any(|(key, _)| key == &pair[0]) {
            return Err(format!("repeated option: {}", pair[0]));
        }
        values.push((pair[0].clone(), pair[1].clone()));
    }
    Ok(values)
}

fn required<'a>(values: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    optional(values, key).ok_or_else(|| format!("{key} required"))
}

fn optional<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn one_path(args: &[String], flag: &str) -> Result<PathBuf, String> {
    let values = options(args, &[flag], &[])?;
    Ok(PathBuf::from(required(&values, flag)?))
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // Keep command dispatch together.
async fn main() -> io::Result<()> {
    let Some(command) = arguments(std::env::args().skip(1)).map_err(io::Error::other)? else {
        println!("{HELP}");
        return Ok(());
    };
    match command {
        Command::ConfigValidate { config } => {
            let config = lumen_config::Config::load(&config).map_err(io::Error::other)?;
            lumen_core::RunningServer::check(&config).await?;
            println!("Lumen configuration valid");
        }
        Command::ConfigApply { config, state } => {
            let parsed = lumen_config::Config::load(&config).map_err(io::Error::other)?;
            lumen_core::RunningServer::check(&parsed).await?;
            let bytes = lumen_config::read_bounded(&config, 65536).map_err(io::Error::other)?;
            let source = std::str::from_utf8(&bytes)
                .map_err(|_| io::Error::other("config must be UTF-8"))?;
            let mut store = Store::open(&state).map_err(io::Error::other)?;
            let revision = store
                .stage_config(source, config.parent().unwrap_or_else(|| Path::new(".")))
                .map_err(io::Error::other)?;
            store
                .enqueue(ControlCommand::ConfigReload(revision))
                .map_err(io::Error::other)?;
            println!("Stored config revision {revision}; reload queued");
        }
        Command::ConfigShow { state } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let config = store
                .config()
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other("state has no active config"))?;
            print!("{}", config.source);
        }
        Command::Control { state, command } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let id = store.enqueue(command).map_err(io::Error::other)?;
            println!("Control command {id} queued");
        }
        Command::Status { state } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let (status, error) = store.status().map_err(io::Error::other)?;
            println!("{}", status.as_deref().unwrap_or("unknown"));
            if let Some(error) = error {
                println!("last error: {error}");
            }
        }
        Command::DeviceList { state } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            for device in store.devices().map_err(io::Error::other)? {
                println!(
                    "{}\t{}\tprofile={}\tgroup={}",
                    device.id,
                    device
                        .addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    device.profile.as_deref().unwrap_or("-"),
                    device.group.as_deref().unwrap_or("-")
                );
            }
        }
        Command::DeviceSet { state, device } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let mut devices = store.devices().map_err(io::Error::other)?;
            if let Some(existing) = devices.iter_mut().find(|item| item.id == device.id) {
                *existing = device.clone();
            } else {
                devices.push(device.clone());
            }
            validate_devices(&store, devices)?;
            store.set_device(&device).map_err(io::Error::other)?;
            store
                .enqueue(ControlCommand::Reload)
                .map_err(io::Error::other)?;
            println!("Device {} stored; reload queued", device.id);
        }
        Command::DeviceRemove { state, id } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let mut devices = store.devices().map_err(io::Error::other)?;
            let count = devices.len();
            devices.retain(|device| device.id != id);
            if devices.len() == count {
                return Err(io::Error::other("device not found"));
            }
            validate_devices(&store, devices)?;
            store.remove_device(&id).map_err(io::Error::other)?;
            store
                .enqueue(ControlCommand::Reload)
                .map_err(io::Error::other)?;
            println!("Device {id} removed; reload queued");
        }
        Command::UserList { state } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            for user in store.users().map_err(io::Error::other)? {
                println!(
                    "{}\t{}{}",
                    user.name,
                    user.role.as_str(),
                    if user.must_change {
                        "\tmust change password"
                    } else {
                        ""
                    }
                );
            }
        }
        Command::UserAdd {
            state,
            name,
            role,
            generate,
        } => {
            let mut store = Store::open(&state).map_err(io::Error::other)?;
            let secret = new_password(generate, &name)?;
            let record = password::hash(&secret).map_err(io::Error::other)?;
            let user = if role == Role::Admin && store.user_count().map_err(io::Error::other)? == 0
            {
                store.create_first_admin(&name, &record)
            } else {
                store.create_user(&name, role, &record, generate)
            }
            .map_err(io::Error::other)?;
            println!("User {} created ({})", user.name, user.role.as_str());
            if generate {
                println!("Temporary password: {secret}");
            }
        }
        Command::User2faReset { state, name } => {
            let store = Store::open(&state).map_err(io::Error::other)?;
            let user = store
                .user_with_record(&name)
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other("unknown user"))?
                .0;
            store.disable_totp(&name).map_err(io::Error::other)?;
            store
                .delete_user_sessions(user.id, None)
                .map_err(io::Error::other)?;
            println!("Two-step verification removed for {name}; their sessions ended");
        }
        Command::UserReset {
            state,
            name,
            generate,
        } => {
            let mut store = Store::open(&state).map_err(io::Error::other)?;
            let secret = new_password(generate, &name)?;
            let record = password::hash(&secret).map_err(io::Error::other)?;
            if !store
                .set_password(&name, &record, generate)
                .map_err(io::Error::other)?
            {
                return Err(io::Error::other("unknown user"));
            }
            println!("Password reset for {name}; all their sessions ended");
            if generate {
                println!("Temporary password: {secret}");
            }
        }
        Command::Explain {
            config,
            client,
            domain,
            at,
        } => {
            let config = lumen_config::Config::load(&config).map_err(io::Error::other)?;
            let filter = lumen_filter::Filter::load(config.filtering)
                .await
                .map_err(io::Error::other)?;
            let at = at.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
            println!("{}", filter.explain(&domain, client, at));
        }
    }
    Ok(())
}

fn validate_devices(store: &Store, devices: Vec<Device>) -> io::Result<()> {
    let stored = store
        .config()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("state has no active config; start managed Lumen first"))?;
    let mut config = lumen_config::Config::parse(&stored.source, Path::new(&stored.base_dir))
        .map_err(io::Error::other)?;
    config.filtering.devices = devices;
    config.validate().map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Command>, String> {
        arguments(args.iter().map(ToString::to_string))
    }

    #[test]
    fn strict_cross_platform_commands() {
        assert!(parse(&["--help"]).unwrap().is_none());
        assert!(parse(&["reload", "--state", "lumen.db"]).is_ok());
        assert!(
            parse(&[
                "config",
                "apply",
                "--config",
                "lumen.toml",
                "--state",
                "lumen.db"
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "device",
                "set",
                "--state",
                "lumen.db",
                "--id",
                "phone",
                "--address",
                "192.0.2.4",
                "--profile",
                "family"
            ])
            .is_ok()
        );
        for args in [
            vec!["reload"],
            vec!["status", "--state", "a", "--state", "b"],
            vec!["device", "set", "--state", "a", "--id", "phone"],
            vec![
                "device",
                "set",
                "--state",
                "a",
                "--id",
                "phone",
                "--address",
                "bad",
            ],
            vec!["filter", "missing", "--state", "a"],
        ] {
            assert!(parse(&args).is_err());
        }
    }

    #[test]
    fn explain_normalizes_domain() {
        let command = parse(&[
            "filter-explain",
            "--config",
            "x",
            "--client",
            "::1",
            "--domain",
            "EXAMPLE.COM.",
            "--at",
            "0",
        ])
        .unwrap()
        .unwrap();
        assert!(
            matches!(command, Command::Explain { domain, at: Some(0), .. } if domain == "example.com")
        );
    }
}
