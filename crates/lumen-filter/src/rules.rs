// SPDX-License-Identifier: Apache-2.0
//! Domain-only parsers. Unsupported Adblock syntax is counted, never widened.

use lumen_proto::hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RULES: usize = 250_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Domains,
    Hosts,
    Adblock,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rule {
    pub domain: String,
    pub exact: bool,
    pub allow: bool,
}
impl Rule {
    /// `=domain` is exact; plain domains and `*.domain` include descendants.
    ///
    /// # Errors
    /// Rejects root rules, paths, regexes, ports, invalid labels, and excess length.
    pub fn parse(text: &str, allow: bool) -> Result<Self, String> {
        let (domain, exact) = text.strip_prefix('=').map_or_else(
            || (text.strip_prefix("*.").unwrap_or(text), false),
            |domain| (domain, true),
        );
        Ok(Self {
            domain: normalize(domain)?,
            exact,
            allow,
        })
    }
}

/// Canonical ASCII/IDNA form without trailing root dot.
///
/// # Errors
/// Rejects syntax that could widen a domain rule or smuggle a URL.
pub fn normalize(text: &str) -> Result<String, String> {
    if text.is_empty()
        || text.len() > 1024
        || text.chars().any(|c| c.is_control() || c.is_whitespace())
        || text.chars().any(|c| "/\\:@^|*=$?#%".contains(c))
    {
        return Err("invalid domain rule".into());
    }
    let name = Name::from_utf8(text).map_err(|_| "invalid IDNA domain")?;
    let ascii = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
    if ascii.is_empty()
        || ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        })
    {
        return Err("invalid domain labels".into());
    }
    Ok(ascii)
}

#[derive(Clone, Debug, Default)]
pub struct ParsedList {
    pub rules: Vec<Rule>,
    pub unsupported: usize,
    pub duplicates: usize,
}

/// Parse an entire bounded UTF-8 list, reporting unsupported Adblock entries.
/// Invalid supported syntax rejects the whole candidate, preserving live state.
///
/// # Errors
/// Rejects byte/line/rule limits, invalid UTF-8, malformed hosts/domain rules,
/// and empty/unsupported-only lists.
pub fn parse(bytes: &[u8], format: Format) -> Result<ParsedList, String> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err("list exceeds 8 MiB".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "list must be UTF-8")?
        .trim_start_matches('\u{feff}');
    let mut result = ParsedList::default();
    let mut seen = HashSet::new();
    for (number, raw) in text.lines().enumerate() {
        if raw.len() > 4096 {
            return Err(format!("list line {} exceeds 4096 bytes", number + 1));
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', '!']) || line.starts_with("[Adblock") {
            continue;
        }
        let mut candidates = Vec::new();
        match format {
            Format::Domains => {
                let line = line.split('#').next().unwrap_or("").trim();
                if !line.is_empty() {
                    candidates.push(Rule::parse(line, false));
                }
            }
            Format::Hosts => {
                let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
                let address = fields
                    .next()
                    .unwrap_or("")
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| format!("invalid hosts address at line {}", number + 1))?;
                if !address.is_loopback() && !address.is_unspecified() {
                    return Err("hosts imports accept sinkhole addresses only".into());
                }
                for host in fields {
                    candidates.push(Rule::parse(host, false));
                }
                if candidates.is_empty() {
                    return Err("hosts entry needs a domain".into());
                }
            }
            Format::Adblock => {
                let (line, allow) = line
                    .strip_prefix("@@")
                    .map_or((line, false), |line| (line, true));
                if let Some(domain) = line
                    .strip_prefix("||")
                    .and_then(|line| line.strip_suffix('^'))
                {
                    candidates.push(Rule::parse(domain, allow));
                } else {
                    result.unsupported += 1;
                    continue;
                }
            }
        }
        for candidate in candidates {
            let rule = candidate.map_err(|_| format!("invalid domain at line {}", number + 1))?;
            if seen.insert(rule.clone()) {
                result.rules.push(rule);
            } else {
                result.duplicates += 1;
            }
            if result.rules.len() > MAX_RULES {
                return Err("list exceeds 250000 rules".into());
            }
        }
    }
    if result.rules.is_empty() {
        return Err("list has no supported rules; use config to remove a list".into());
    }
    Ok(result)
}

// Wire labels may contain arbitrary octets. Keep real label boundaries so an
// unusual child label cannot bypass a suffix block (or invent a false suffix).
pub(crate) fn wire_name(name: &Name) -> String {
    name.iter()
        .map(|label| {
            if label
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(c))
            {
                String::from_utf8_lossy(label).to_ascii_lowercase()
            } else {
                // This sentinel can never occur in a configured rule.
                "!".to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}
