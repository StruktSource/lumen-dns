//! Turning a stream of check results into a device state, without crying wolf.
//!
//! One lost packet never raises an outage: a device goes offline only after a configured number
//! of failed checks in a row, and comes back on the first success. A device that still answers
//! but loses a large share of recent checks is degraded.

use crate::model::Status;
use lumen_config::Monitor;
use std::collections::VecDeque;

/// How many recent checks the loss figure covers.
const WINDOW: usize = 10;
/// Fewest checks before loss can mark a device degraded.
const MIN_SAMPLES: usize = 5;

/// The result of one check: probes sent, and how many were answered.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CheckResult {
    pub sent: u8,
    pub received: u8,
    pub rtt_ms: Option<f64>,
}

impl CheckResult {
    #[must_use]
    pub fn ok(self) -> bool {
        self.received > 0
    }
    #[must_use]
    pub fn loss_percent(self) -> f64 {
        if self.sent == 0 {
            100.0
        } else {
            100.0 * f64::from(self.sent - self.received.min(self.sent)) / f64::from(self.sent)
        }
    }
}

/// A change worth telling someone about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transition {
    /// Went offline after enough failed checks.
    Offline,
    /// Answers again after an outage.
    Recovered,
    /// Answers, but loses too much.
    Degraded,
    /// Loss is back to normal.
    Healthy,
}

impl Transition {
    #[must_use]
    pub fn event(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Recovered => "recovered",
            Self::Degraded => "degraded",
            Self::Healthy => "online",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Health {
    pub status: Status,
    pub fail_streak: u32,
    window: VecDeque<f64>,
}

impl Health {
    /// Start from what is stored. Recent loss starts empty, so a restart never degrades a device.
    #[must_use]
    pub fn new(status: Status, fail_streak: u32) -> Self {
        Self {
            status,
            fail_streak,
            window: VecDeque::new(),
        }
    }

    /// Recent packet loss over the last checks, or `None` before there are enough of them.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn loss_percent(&self) -> Option<f64> {
        (self.window.len() >= MIN_SAMPLES)
            .then(|| self.window.iter().sum::<f64>() / self.window.len() as f64)
    }

    /// Take in a check and say whether the state changed.
    pub fn apply(&mut self, result: CheckResult, monitor: &Monitor) -> Option<Transition> {
        self.window.push_back(result.loss_percent());
        while self.window.len() > WINDOW {
            self.window.pop_front();
        }
        let before = self.status;
        let lossy = self
            .loss_percent()
            .is_some_and(|loss| loss >= f64::from(monitor.degraded_loss_percent));
        if result.ok() {
            self.fail_streak = 0;
            if before == Status::Offline {
                // Back from an outage: the outage's lost checks are not packet loss.
                self.window.clear();
                self.window.push_back(result.loss_percent());
            }
            let lossy = before != Status::Offline && lossy;
            self.status = if lossy {
                Status::Degraded
            } else {
                Status::Online
            };
        } else {
            // A failed check counts toward an outage. Degraded means "answers, but loses too
            // much", so it is judged only when the device answers.
            self.fail_streak = self.fail_streak.saturating_add(1);
            if self.fail_streak >= u32::from(monitor.failures_before_offline) {
                self.status = Status::Offline;
            }
        }
        match (before, self.status) {
            (Status::Offline, Status::Online | Status::Degraded) => Some(Transition::Recovered),
            (b, Status::Offline) if b != Status::Offline => Some(Transition::Offline),
            (Status::Online | Status::Unknown, Status::Degraded) => Some(Transition::Degraded),
            (Status::Degraded, Status::Online) => Some(Transition::Healthy),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> Monitor {
        Monitor {
            failures_before_offline: 3,
            degraded_loss_percent: 20,
            ..Monitor::default()
        }
    }
    const UP: CheckResult = CheckResult {
        sent: 3,
        received: 3,
        rtt_ms: Some(1.0),
    };
    const DOWN: CheckResult = CheckResult {
        sent: 3,
        received: 0,
        rtt_ms: None,
    };

    #[test]
    fn a_few_lost_checks_do_not_raise_an_outage_but_enough_do() {
        let m = monitor();
        let mut h = Health::new(Status::Unknown, 0);
        assert_eq!(h.apply(UP, &m), None, "unknown to online is not an alert");
        assert_eq!(h.status, Status::Online);
        assert_eq!(h.apply(DOWN, &m), None);
        assert_eq!(h.apply(DOWN, &m), None);
        assert_eq!(h.status, Status::Online, "two failures are still a blip");
        assert_eq!(h.apply(UP, &m), None);
        assert_eq!(h.fail_streak, 0, "a success starts the count again");
        for _ in 0..2 {
            assert_eq!(h.apply(DOWN, &m), None);
        }
        assert_eq!(h.apply(DOWN, &m), Some(Transition::Offline));
        assert_eq!(h.status, Status::Offline);
        assert_eq!(h.apply(DOWN, &m), None, "an outage is reported once");
        assert_eq!(h.apply(UP, &m), Some(Transition::Recovered));
        assert_eq!(h.status, Status::Online);
    }

    #[test]
    fn loss_makes_a_device_degraded_and_clears_when_it_stops() {
        let m = monitor();
        let mut h = Health::new(Status::Online, 0);
        let lossy = CheckResult {
            sent: 3,
            received: 1,
            rtt_ms: Some(5.0),
        };
        for _ in 0..4 {
            assert_eq!(h.apply(lossy, &m), None, "too few samples to judge");
        }
        assert_eq!(h.apply(lossy, &m), Some(Transition::Degraded));
        assert_eq!(h.status, Status::Degraded);
        let mut change = None;
        for _ in 0..WINDOW {
            change = h.apply(UP, &m).or(change);
        }
        assert_eq!(change, Some(Transition::Healthy));
        assert_eq!(h.status, Status::Online);
    }

    #[test]
    fn a_restart_does_not_invent_loss_and_an_unknown_device_needs_all_its_failures() {
        let m = monitor();
        let mut h = Health::new(Status::Online, 0);
        assert_eq!(h.apply(UP, &m), None);
        assert!(h.loss_percent().is_none());
        let mut fresh = Health::new(Status::Unknown, 0);
        assert_eq!(fresh.apply(DOWN, &m), None);
        assert_eq!(fresh.status, Status::Unknown);
        fresh.apply(DOWN, &m);
        assert_eq!(fresh.apply(DOWN, &m), Some(Transition::Offline));
        let one = Monitor {
            failures_before_offline: 1,
            ..monitor()
        };
        assert_eq!(
            Health::new(Status::Online, 0).apply(DOWN, &one),
            Some(Transition::Offline)
        );
    }
}
