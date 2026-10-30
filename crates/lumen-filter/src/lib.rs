// SPDX-License-Identifier: Apache-2.0
//! Client-aware filtering before DNS cache lookup. Updates are transactional.

pub mod config;
mod fetch;
mod response;
pub mod rules;
pub use response::response;

use config::{Action, Config, Profile, Rules};
use rules::{ParsedList, Rule};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub blocked: bool,
    pub rule: Option<String>,
    pub list: Option<String>,
    pub category: Option<String>,
    pub profile: Option<String>,
    pub device: Option<String>,
    pub group: Option<String>,
    pub action: Option<Action>,
    pub generation: u64,
}
impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "blocked={} rule={:?} list={:?} category={:?} profile={:?} device={:?} group={:?} action={:?} generation={}",
            self.blocked,
            self.rule,
            self.list,
            self.category,
            self.profile,
            self.device,
            self.group,
            self.action,
            self.generation
        )
    }
}

#[derive(Default)]
pub struct Metrics {
    pub blocked: AtomicU64,
    pub allowed: AtomicU64,
    pub refresh_successes: AtomicU64,
    pub refresh_failures: AtomicU64,
    pub rollbacks: AtomicU64,
}

impl Metrics {
    /// Aggregate counters only; no domains, client addresses, or policy labels.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();
        for (name, value) in [
            ("blocked", &self.blocked),
            ("allowed", &self.allowed),
            ("refresh_successes", &self.refresh_successes),
            ("refresh_failures", &self.refresh_failures),
            ("rollbacks", &self.rollbacks),
        ] {
            let _ = writeln!(
                output,
                "# TYPE lumen_filter_{name}_total counter\nlumen_filter_{name}_total {}",
                value.load(Ordering::Relaxed)
            );
        }
        output
    }
}

#[derive(Clone)]
struct Entry {
    rule: Rule,
    list: Option<usize>,
}
#[derive(Default)]
struct Index(HashMap<String, Vec<Entry>>);
impl Index {
    fn insert(&mut self, rule: Rule, list: Option<usize>) {
        self.0
            .entry(rule.domain.clone())
            .or_default()
            .push(Entry { rule, list });
    }
    fn manual(rules: &Rules) -> Result<Self, String> {
        let mut index = Self::default();
        for (values, allow) in [(&rules.allow, true), (&rules.block, false)] {
            for value in values {
                index.insert(Rule::parse(value, allow)?, None);
            }
        }
        Ok(index)
    }
    fn find(&self, name: &str, eligible: impl Fn(Option<usize>) -> bool) -> Option<&Entry> {
        let mut suffix = name;
        let mut blocked = None;
        loop {
            if let Some(entries) = self.0.get(suffix) {
                for entry in entries {
                    if (entry.rule.exact && suffix != name) || !eligible(entry.list) {
                        continue;
                    }
                    if entry.rule.allow {
                        return Some(entry);
                    }
                    if blocked.is_none() {
                        blocked = Some(entry);
                    }
                }
            }
            let Some((_, next)) = suffix.split_once('.') else {
                break;
            };
            suffix = next;
        }
        blocked
    }
}

struct Snapshot {
    lists: Vec<Arc<ParsedList>>,
    index: Index,
    generation: u64,
}
struct State {
    live: Arc<Snapshot>,
    previous: Option<Arc<Snapshot>>,
}
struct Refresh {
    attempted: Vec<Instant>,
    generation: u64,
    automatic_paused: bool,
}

pub struct Filter {
    config: Config,
    global: Index,
    profiles: Vec<Index>,
    devices: HashMap<IpAddr, usize>,
    state: RwLock<State>,
    refresh: Mutex<Refresh>,
    pub metrics: Metrics,
}

impl Filter {
    /// Load and validate every source before serving any query.
    ///
    /// # Errors
    /// A failed, empty, malformed, or oversized source fails startup.
    pub async fn load(config: Config) -> Result<Self, String> {
        config.validate()?;
        let mut lists = Vec::new();
        for source in &config.lists {
            lists.push(Arc::new(load_list(source).await?));
            check_rule_budget(&config, &lists)?;
        }
        let live = Arc::new(compile(&config, lists, 1)?);
        let global = Index::manual(&config.rules)?;
        let profiles = config
            .profiles
            .iter()
            .map(|p| Index::manual(&p.rules))
            .collect::<Result<_, _>>()?;
        let devices = config
            .devices
            .iter()
            .enumerate()
            .flat_map(|(i, device)| {
                device
                    .addresses
                    .iter()
                    .map(move |ip| (ip.to_canonical(), i))
            })
            .collect();
        let attempted = vec![Instant::now(); config.lists.len()];
        Ok(Self {
            config,
            global,
            profiles,
            devices,
            state: RwLock::new(State {
                live,
                previous: None,
            }),
            refresh: Mutex::new(Refresh {
                attempted,
                generation: 1,
                automatic_paused: false,
            }),
            metrics: Metrics::default(),
        })
    }

    /// Explain without recording a query or changing aggregate counters.
    ///
    /// # Panics
    /// Panics if an internal writer previously poisoned the snapshot lock.
    #[must_use]
    pub fn explain(&self, domain: &str, client: IpAddr, unix_seconds: u64) -> Decision {
        self.explain_canonical(
            &rules::normalize(domain).unwrap_or_default(),
            client,
            unix_seconds,
        )
    }

    /// Explain a decoded DNS name without a lossy presentation-string round trip.
    ///
    /// # Panics
    /// Panics if an internal writer previously poisoned the snapshot lock.
    #[must_use]
    pub fn explain_dns(
        &self,
        name: &lumen_proto::hickory_proto::rr::Name,
        client: IpAddr,
        unix_seconds: u64,
    ) -> Decision {
        self.explain_canonical(&rules::wire_name(name), client, unix_seconds)
    }

    fn explain_canonical(&self, name: &str, client: IpAddr, unix_seconds: u64) -> Decision {
        let live = Arc::clone(&self.state.read().expect("filter state lock").live);
        let device = self
            .devices
            .get(&client.to_canonical())
            .map(|i| &self.config.devices[*i]);
        let group = device
            .and_then(|d| d.group.as_ref())
            .and_then(|id| self.config.groups.iter().find(|g| &g.id == id));
        let profile_id = device
            .and_then(|d| d.profile.as_deref())
            .or_else(|| group.map(|g| g.profile.as_str()))
            .or_else(|| {
                self.config
                    .subnets
                    .iter()
                    .filter(|s| s.network.contains(&client.to_canonical()))
                    .max_by_key(|s| s.network.prefix_len())
                    .map(|s| s.profile.as_str())
            })
            .or(self.config.default_profile.as_deref());
        let profile = profile_id.and_then(|id| {
            self.config
                .profiles
                .iter()
                .enumerate()
                .find(|(_, p)| p.id == id)
        });
        let active = profile.filter(|(_, p)| {
            p.schedules.is_empty() || p.schedules.iter().any(|s| s.active(unix_seconds))
        });
        let mut decision = Decision {
            blocked: false,
            rule: None,
            list: None,
            category: None,
            profile: profile_id.map(str::to_owned),
            device: device.map(|d| d.id.clone()),
            group: group.map(|g| g.id.clone()),
            action: None,
            generation: live.generation,
        };
        let found = active
            .and_then(|(i, _)| self.profiles[i].find(name, |_| true))
            .or_else(|| self.global.find(name, |_| true))
            .or_else(|| {
                live.index.find(name, |list| {
                    let list = &self.config.lists[list.expect("list index")];
                    match profile {
                        Some(_) if active.is_none() => false,
                        Some((_, p)) => selected(p, list),
                        None => list.category.is_none(),
                    }
                })
            });
        if let Some(entry) = found {
            decision.blocked = !entry.rule.allow;
            decision.rule = Some(format!(
                "{}{}",
                if entry.rule.exact { "=" } else { "" },
                entry.rule.domain
            ));
            if let Some(i) = entry.list {
                decision.list = Some(self.config.lists[i].id.clone());
                decision.category.clone_from(&self.config.lists[i].category);
            }
            if decision.blocked {
                decision.action = Some(
                    active
                        .and_then(|(_, p)| p.action.clone())
                        .unwrap_or_else(|| self.config.action.clone()),
                );
            }
        }
        decision
    }

    /// Decide and count; called once per admitted DNS request before resolution.
    #[must_use]
    pub fn decide(&self, domain: &str, client: IpAddr, unix_seconds: u64) -> Decision {
        let decision = self.explain(domain, client, unix_seconds);
        self.count(decision)
    }

    /// Decide directly on wire labels and count one admitted request.
    #[must_use]
    pub fn decide_dns(
        &self,
        name: &lumen_proto::hickory_proto::rr::Name,
        client: IpAddr,
        unix_seconds: u64,
    ) -> Decision {
        self.count(self.explain_dns(name, client, unix_seconds))
    }

    fn count(&self, decision: Decision) -> Decision {
        if decision.blocked {
            &self.metrics.blocked
        } else {
            &self.metrics.allowed
        }
        .fetch_add(1, Ordering::Relaxed);
        decision
    }

    /// Refresh all sources as one transaction. Failed updates retain live/previous state.
    ///
    /// # Errors
    /// Returns a bounded source/validation error. No partial policy is published.
    pub async fn refresh(&self) -> Result<(), String> {
        self.update(true).await.map(|_| ())
    }

    /// Refresh due sources, retaining unchanged list snapshots.
    ///
    /// # Errors
    /// Returns a candidate error without affecting live filtering.
    pub async fn refresh_due(&self) -> Result<bool, String> {
        self.update(false).await
    }

    async fn update(&self, force: bool) -> Result<bool, String> {
        let mut refresh = self.refresh.lock().await;
        if !force && refresh.automatic_paused {
            return Ok(false);
        }
        let now = Instant::now();
        let due: Vec<usize> = self
            .config
            .lists
            .iter()
            .enumerate()
            .filter(|(i, list)| {
                force
                    || (list.refresh_secs != 0
                        && now.duration_since(refresh.attempted[*i])
                            >= Duration::from_secs(u64::from(list.refresh_secs)))
            })
            .map(|(i, _)| i)
            .collect();
        if due.is_empty() {
            return Ok(false);
        }
        for i in &due {
            refresh.attempted[*i] = now;
        }
        let mut lists = self
            .state
            .read()
            .expect("filter state lock")
            .live
            .lists
            .clone();
        let result = async {
            for i in due {
                lists[i] = Arc::new(load_list(&self.config.lists[i]).await?);
                check_rule_budget(&self.config, &lists)?;
            }
            let config = self.config.clone();
            let generation = refresh.generation + 1;
            tokio::task::spawn_blocking(move || compile(&config, lists, generation))
                .await
                .map_err(|_| "filter compiler stopped")?
        }
        .await;
        match result {
            Ok(candidate) => {
                let mut state = self.state.write().expect("filter state lock");
                let old = std::mem::replace(&mut state.live, Arc::new(candidate));
                state.previous = Some(old);
                refresh.generation += 1;
                refresh.automatic_paused = false;
                self.metrics
                    .refresh_successes
                    .fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(error) => {
                self.metrics
                    .refresh_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    /// Swap back to the previous validated generation. Only one generation retained.
    ///
    /// # Errors
    /// No previous successful generation exists until the first refresh.
    ///
    /// # Panics
    /// Panics if an internal writer previously poisoned the snapshot lock.
    pub async fn rollback(&self) -> Result<(), String> {
        let mut refresh = self.refresh.lock().await;
        let mut state = self.state.write().expect("filter state lock");
        let previous = state.previous.take().ok_or("no previous list generation")?;
        let old = std::mem::replace(&mut state.live, previous);
        state.previous = Some(old);
        refresh.automatic_paused = true;
        self.metrics.rollbacks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn selected(profile: &Profile, list: &config::List) -> bool {
    (profile.lists.is_empty() || profile.lists.contains(&list.id))
        && list
            .category
            .as_ref()
            .is_none_or(|category| profile.categories.contains(category))
}
fn compile(
    config: &Config,
    lists: Vec<Arc<ParsedList>>,
    generation: u64,
) -> Result<Snapshot, String> {
    check_rule_budget(config, &lists)?;
    let mut index = Index::default();
    for (i, list) in lists.iter().enumerate() {
        for rule in &list.rules {
            index.insert(rule.clone(), Some(i));
        }
    }
    Ok(Snapshot {
        lists,
        index,
        generation,
    })
}
fn check_rule_budget(config: &Config, lists: &[Arc<ParsedList>]) -> Result<(), String> {
    let manual = config.rules.allow.len()
        + config.rules.block.len()
        + config
            .profiles
            .iter()
            .map(|p| p.rules.allow.len() + p.rules.block.len())
            .sum::<usize>();
    if manual + lists.iter().map(|l| l.rules.len()).sum::<usize>() > rules::MAX_RULES {
        return Err("all filtering rules together exceed 250000".into());
    }
    Ok(())
}
async fn load_list(source: &config::List) -> Result<ParsedList, String> {
    let source = source.clone();
    let bytes = if let Some(url) = &source.url {
        fetch::download(url).await?
    } else {
        let source = source.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            if let Some(path) = &source.path {
                if !std::fs::metadata(path)
                    .map_err(|_| "cannot inspect filter list")?
                    .is_file()
                {
                    return Err("filter list must be a regular file".into());
                }
                let mut bytes = Vec::new();
                std::fs::File::open(path)
                    .map_err(|_| "cannot open filter list")?
                    .take((rules::MAX_LIST_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "cannot read filter list")?;
                Ok::<_, String>(bytes)
            } else {
                Ok(source.text.unwrap_or_default().into_bytes())
            }
        })
        .await
        .map_err(|_| "filter file reader stopped")??
    };
    tokio::task::spawn_blocking(move || rules::parse(&bytes, source.format))
        .await
        .map_err(|_| "filter parser stopped")?
}

#[cfg(test)]
mod tests;
