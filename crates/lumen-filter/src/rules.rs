// SPDX-License-Identifier: Apache-2.0
//! Domain-only parsers. Unsupported Adblock syntax is counted, never widened.

use lumen_proto::hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, hash::BuildHasher, sync::OnceLock};

/// Largest list body accepted (large public lists run to several MiB).
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;
/// Rules across all lists and manual tiers. Each list rule costs 8 bytes in memory (4M rules is about 32 MB).
pub const MAX_RULES: usize = 4_000_000;

/// Keyed 62-bit hash of a canonical domain. The key is random per process, so lists
/// cannot be crafted to collide, and the hash is never stored or shown.
#[must_use]
pub fn domain_hash(domain: &str) -> u64 {
    static STATE: OnceLock<std::hash::RandomState> = OnceLock::new();
    STATE
        .get_or_init(std::hash::RandomState::new)
        .hash_one(domain)
        >> 2
}

/// One list rule in 8 bytes: a 62-bit domain hash plus `allow` and `exact` flag bits.
/// The domain itself is not kept; a match is named from the query's own suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleKey(u64);

impl RuleKey {
    #[must_use]
    pub fn new(rule: &Rule) -> Self {
        Self(
            (domain_hash(&rule.domain) << 2) | u64::from(rule.allow) | (u64::from(rule.exact) << 1),
        )
    }
    #[must_use]
    pub const fn allow(self) -> bool {
        self.0 & 1 != 0
    }
    #[must_use]
    pub const fn exact(self) -> bool {
        self.0 & 2 != 0
    }
    const fn hash(self) -> u64 {
        self.0 >> 2
    }
}

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
    /// Sorted, so a domain's rules are found with one binary search.
    pub rules: Vec<RuleKey>,
    pub unsupported: usize,
    pub duplicates: usize,
}

impl ParsedList {
    /// Rules whose domain hashes to `hash` (at most a handful: allow/block, exact/suffix).
    pub fn lookup(&self, hash: u64) -> impl Iterator<Item = RuleKey> + '_ {
        let start = self.rules.partition_point(|key| key.hash() < hash);
        self.rules[start..]
            .iter()
            .copied()
            .take_while(move |key| key.hash() == hash)
    }
}

/// Parse an entire bounded UTF-8 list, counting unsupported Adblock syntax and domains
/// that fail validation (they are skipped, never widened). A list with no usable rule is
/// rejected whole, preserving live state.
///
/// # Errors
/// Rejects byte/line/rule limits, invalid UTF-8, malformed hosts/domain rules,
/// and empty/unsupported-only lists.
pub fn parse(bytes: &[u8], format: Format) -> Result<ParsedList, String> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err("list exceeds the 64 MiB size limit".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "list must be UTF-8")?
        .trim_start_matches('\u{feff}');
    let mut result = ParsedList::default();
    let mut seen: HashSet<RuleKey> = HashSet::new();
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
            // One malformed name in a public list must not make the whole list unusable.
            // Skipping it can only leave that name unblocked, never widen a rule; it is
            // counted with the other unsupported entries.
            let Ok(rule) = candidate else {
                result.unsupported += 1;
                continue;
            };
            let key = RuleKey::new(&rule);
            if seen.insert(key) {
                result.rules.push(key);
            } else {
                result.duplicates += 1;
            }
            if result.rules.len() > MAX_RULES {
                return Err(format!("list exceeds {MAX_RULES} rules"));
            }
        }
    }
    if result.rules.is_empty() {
        return Err("list has no supported rules; use config to remove a list".into());
    }
    drop(seen);
    result.rules.sort_unstable();
    result.rules.shrink_to_fit();
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
