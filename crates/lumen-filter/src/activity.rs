// SPDX-License-Identifier: Apache-2.0
//! Live progress of list downloads and configuration applies, for the console.
//!
//! This is operational state only (list names, byte counts, error text). It holds
//! no client data and is lost on restart.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

tokio::task_local! {
    static CURRENT: String;
}

/// The overall job the daemon is working on.
#[derive(Clone, Debug)]
pub struct Job {
    /// `idle`, `checking`, `downloading`, `starting`, `done` or `failed`.
    pub phase: &'static str,
    pub message: String,
    /// Unix seconds when the phase began.
    pub since: u64,
}

/// One list in the current batch.
#[derive(Clone, Debug)]
pub struct ListProgress {
    pub id: String,
    /// `waiting`, `downloading`, `parsing`, `ready` or `failed`.
    pub state: &'static str,
    pub bytes: u64,
    pub total: Option<u64>,
    pub rules: usize,
    pub error: Option<String>,
}

struct State {
    job: Job,
    lists: Vec<ListProgress>,
}

static STATE: Mutex<State> = Mutex::new(State {
    job: Job {
        phase: "idle",
        message: String::new(),
        since: 0,
    },
    lists: Vec::new(),
});

/// Set by [`request_cancel`], cleared when the next batch begins.
static CANCEL: AtomicBool = AtomicBool::new(false);

/// Ask whatever is downloading or checking lists right now to stop. The change that
/// started it is then not applied and the previous settings stay live.
/// Returns whether anything was running to cancel.
pub fn request_cancel() -> bool {
    let running = with(|s| busy(s.job.phase));
    if running {
        CANCEL.store(true, Ordering::SeqCst);
    }
    running
}

/// Whether a cancel is pending for the current job.
pub(crate) fn cancel_requested() -> bool {
    CANCEL.load(Ordering::SeqCst)
}

fn busy(phase: &str) -> bool {
    matches!(phase, "checking" | "downloading")
}

/// Completes when a cancel is requested. Polled slowly: it only runs during downloads.
pub(crate) async fn cancelled() {
    while !cancel_requested() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut state = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut state)
}

/// Record the daemon's current phase.
pub fn set_job(phase: &'static str, message: impl Into<String>) {
    let message = message.into();
    with(|s| {
        // A job that starts from a finished or idle state never inherits an old cancel.
        if !busy(s.job.phase) {
            CANCEL.store(false, Ordering::SeqCst);
        }
        s.job = Job {
            phase,
            message,
            since: now(),
        };
    });
}

/// Start a new batch: every id is waiting.
pub fn begin_lists<'a>(ids: impl Iterator<Item = &'a str>) {
    with(|s| {
        s.lists = ids
            .map(|id| ListProgress {
                id: id.to_owned(),
                state: "waiting",
                bytes: 0,
                total: None,
                rules: 0,
                error: None,
            })
            .collect();
    });
}

fn update(id: &str, f: impl FnOnce(&mut ListProgress)) {
    with(|s| {
        if let Some(item) = s.lists.iter_mut().find(|l| l.id == id) {
            f(item);
        }
    });
}

pub(crate) fn state(id: &str, value: &'static str) {
    update(id, |l| l.state = value);
}

pub(crate) fn ready(id: &str, rules: usize) {
    update(id, |l| {
        l.state = "ready";
        l.rules = rules;
        l.error = None;
    });
}

pub(crate) fn failed(id: &str, error: &str) {
    update(id, |l| {
        l.state = "failed";
        l.error = Some(error.to_owned());
    });
}

/// Bytes received so far for whichever list the current task is loading.
pub(crate) fn bytes(received: u64, total: Option<u64>) {
    let _ = CURRENT.try_with(|id| {
        update(id, |l| {
            l.state = "downloading";
            l.bytes = received;
            l.total = total;
        });
    });
}

pub(crate) async fn scope<F: std::future::Future>(id: &str, future: F) -> F::Output {
    CURRENT.scope(id.to_owned(), future).await
}

/// Copy of the current job and list batch.
#[must_use]
pub fn snapshot() -> (Job, Vec<ListProgress>) {
    with(|s| (s.job.clone(), s.lists.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn progress_follows_one_list_through_its_states() {
        begin_lists(["alpha", "beta"].into_iter());
        let (_, lists) = snapshot();
        assert!(lists.iter().all(|l| l.state == "waiting"));
        scope("alpha", async { bytes(10, Some(100)) }).await;
        bytes(5, None); // outside any list: ignored
        ready("alpha", 7);
        failed("beta", "boom");
        set_job("failed", "nope");
        let (job, lists) = snapshot();
        assert_eq!((job.phase, job.message.as_str()), ("failed", "nope"));
        assert_eq!(
            (lists[0].state, lists[0].rules, lists[0].total),
            ("ready", 7, Some(100))
        );
        assert_eq!(
            (lists[1].state, lists[1].error.as_deref()),
            ("failed", Some("boom"))
        );
    }
}
