// SPDX-License-Identifier: Apache-2.0
//! Cancelling an apply. This lives in its own test process because activity state is global.

use lumen_filter::{
    Filter, activity,
    config::{Config, List},
    rules::Format,
};

fn config() -> Config {
    Config {
        lists: vec![List {
            id: "inline".into(),
            format: Format::Domains,
            path: None,
            url: None,
            text: Some("ads.example\n".into()),
            category: None,
            refresh_secs: 0,
        }],
        ..Config::default()
    }
}

#[tokio::test]
async fn cancel_stops_a_running_apply_and_the_next_job_starts_clean() {
    // Nothing is running, so there is nothing to cancel and a later job is unaffected.
    activity::set_job("idle", "");
    assert!(!activity::request_cancel());
    activity::set_job("checking", "Checking");
    assert!(Filter::load(config()).await.is_ok());

    // A cancel during a running job makes the load stop with a clear message.
    activity::set_job("downloading", "Downloading");
    assert!(activity::request_cancel());
    let error = Filter::load(config()).await.err().expect("cancelled");
    assert_eq!(error, "download cancelled");

    // The failed job is over. The next one is not cancelled by the old request.
    activity::set_job("failed", "Not applied");
    activity::set_job("checking", "Checking");
    assert!(Filter::load(config()).await.is_ok());
    activity::set_job("idle", "");
}
