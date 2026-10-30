// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use lumen_filter::rules::{Format, parse};
fuzz_target!(|input: &[u8]| {
    if input.len() <= 65536 {
        for format in [Format::Domains, Format::Hosts, Format::Adblock] {
            let _ = parse(input, format);
        }
    }
});
