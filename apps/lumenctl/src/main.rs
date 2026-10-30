// SPDX-License-Identifier: Apache-2.0
//! Local, read-only policy diagnosis. No management listener is exposed.
use std::{
    io,
    net::IpAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const HELP: &str = "Usage: lumenctl filter-explain --config FILE --client IP --domain NAME [--at UNIX_SECONDS]\n\nLoads configured lists (including HTTPS sources), then explains a decision.\nNo DNS query is sent. --at selects a UTC instant for schedule checks.";

#[derive(Debug, PartialEq, Eq)]
struct Explain {
    path: PathBuf,
    client: IpAddr,
    domain: String,
    at: Option<u64>,
}

fn arguments(args: impl IntoIterator<Item = String>) -> Result<Option<Explain>, String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None => return Ok(None),
        Some("--help" | "-h") if args.next().is_none() => return Ok(None),
        Some("filter-explain") => (),
        _ => return Err(HELP.into()),
    }
    let (mut path, mut client, mut domain, mut at) = (None, None, None, None);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("missing option value")?;
        match flag.as_str() {
            "--config" if path.is_none() => path = Some(PathBuf::from(value)),
            "--client" if client.is_none() => {
                client = Some(value.parse().map_err(|_| "invalid client IP")?);
            }
            "--domain" if domain.is_none() => {
                domain = Some(lumen_filter::rules::normalize(&value)?);
            }
            "--at" if at.is_none() => at = Some(value.parse().map_err(|_| "invalid Unix time")?),
            _ => return Err("unknown or repeated option".into()),
        }
    }
    Ok(Some(Explain {
        path: path.ok_or("--config required")?,
        client: client.ok_or("--client required")?,
        domain: domain.ok_or("--domain required")?,
        at,
    }))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let Some(args) = arguments(std::env::args().skip(1)).map_err(io::Error::other)? else {
        println!("{HELP}");
        return Ok(());
    };
    let config = lumen_config::Config::load(&args.path).map_err(io::Error::other)?;
    let filter = lumen_filter::Filter::load(config.filtering)
        .await
        .map_err(io::Error::other)?;
    let at = args.at.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    println!("{}", filter.explain(&args.domain, args.client, at));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_arguments() {
        let parse = |args: &[&str]| arguments(args.iter().map(ToString::to_string));
        assert!(parse(&["--help"]).unwrap().is_none());
        for args in [
            vec!["filter-explain"],
            vec!["--help", "extra"],
            vec!["filter-explain", "--client", "bad"],
            vec!["filter-explain", "--config", "x", "--config", "y"],
        ] {
            assert!(parse(&args).is_err());
        }
        let result = parse(&[
            "filter-explain",
            "--config",
            "config.toml",
            "--client",
            "::1",
            "--domain",
            "EXAMPLE.COM.",
            "--at",
            "0",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.at, Some(0));
    }
}
