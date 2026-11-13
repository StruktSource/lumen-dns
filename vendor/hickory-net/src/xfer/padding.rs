// LUMEN PATCH: EDNS(0) padding for encrypted transports (RFC 7830, block sizes per RFC 8467).

use hickory_proto::{
    op::Message,
    rr::rdata::opt::{EdnsCode, EdnsOption},
};

/// Block length for padded queries (RFC 8467 section 4.1: clients pad to a multiple of 128).
pub const QUERY_BLOCK: usize = 128;

/// Pads `message` with an EDNS(0) Padding option so its encoded length is a multiple of `block`.
///
/// A message without an OPT record is left alone (padding needs one). A zero `block` does
/// nothing. Any padding option already present is replaced.
pub fn pad_message(message: &mut Message, block: usize) {
    if block == 0 {
        return;
    }
    let Some(edns) = message.edns.as_mut() else {
        return;
    };
    edns.options_mut().remove(EdnsCode::Padding);
    let Ok(plain) = message.to_vec() else {
        return;
    };
    // An empty padding option costs 4 bytes (code and length).
    let total = (plain.len() + 4).div_ceil(block) * block;
    let fill = total - plain.len() - 4;
    if let Some(edns) = message.edns.as_mut() {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; fill]));
    }
}
