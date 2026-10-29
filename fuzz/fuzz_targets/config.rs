// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &str| {
    if input.len() <= 65536 {
        if let Ok(config) = toml::from_str::<lumen_config::Config>(input) {
            let _ = config.validate();
        }
    }
});
