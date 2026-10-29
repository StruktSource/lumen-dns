// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    if input.len() <= lumen_proto::MAX_MESSAGE_SIZE {
        let _ = lumen_proto::decode_message(input);
        if let Ok(query) = lumen_proto::Query::parse(input) {
            let response = query.response(lumen_proto::Rcode::ServFail);
            assert!(lumen_proto::decode_message(&response).is_ok());
        }
        assert_eq!(lumen_proto::malformed_response(input).len(), 12);
    }
});
