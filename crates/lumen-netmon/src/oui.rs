//! Manufacturer names from the first three bytes of a MAC address.
//!
//! The built-in list is the public IEEE MA-L registry (see `data/README`), and `oui_file` can add
//! or replace entries from a newer `oui.txt`.

use std::{collections::HashMap, sync::OnceLock};

static BUILTIN: &str = include_str!("../data/oui.tsv");

fn builtin() -> &'static HashMap<u32, &'static str> {
    static MAP: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        BUILTIN
            .lines()
            .filter_map(|line| {
                let (prefix, name) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, name))
            })
            .collect()
    })
}

/// A vendor list. Cheap to build: the built-in table is shared.
#[derive(Clone, Debug, Default)]
pub struct Oui {
    extra: HashMap<u32, String>,
}

/// A hardware address.
pub type Mac = [u8; 6];

/// `aa:bb:cc:dd:ee:ff`, also accepting `-` and no separator and missing leading zeros (macOS
/// prints `0:1b:63:...`).
#[must_use]
pub fn parse_mac(text: &str) -> Option<Mac> {
    let text = text.trim();
    let parts: Vec<&str> = if text.contains(':') || text.contains('-') {
        text.split([':', '-']).collect()
    } else if text.len() == 12 {
        (0..6).map(|i| &text[i * 2..i * 2 + 2]).collect()
    } else {
        return None;
    };
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

#[must_use]
pub fn format_mac(mac: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Not a real manufacturer's address: the "locally administered" bit is set, as in the private
/// (randomized) addresses phones use, and in many virtual machines.
#[must_use]
pub fn is_local(mac: &Mac) -> bool {
    mac[0] & 0x02 != 0
}

/// Group (multicast and broadcast) and all-zero addresses never belong to one device.
#[must_use]
pub fn is_usable(mac: &Mac) -> bool {
    mac[0] & 0x01 == 0 && mac.iter().any(|b| *b != 0)
}

impl Oui {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add entries from an IEEE `oui.txt` (`AA-BB-CC   (hex)\t\tVendor`) or the `AABBCC<TAB>Vendor`
    /// form. Returns how many were read.
    pub fn load(&mut self, text: &str) -> usize {
        let before = self.extra.len();
        for line in text.lines() {
            let (prefix, name) = if let Some((prefix, rest)) = line.split_once("(hex)") {
                (prefix.trim().replace('-', ""), rest.trim())
            } else if let Some((prefix, name)) = line.split_once('\t') {
                (prefix.trim().to_owned(), name.trim())
            } else {
                continue;
            };
            if prefix.len() == 6
                && !name.is_empty()
                && name.len() <= 120
                && let Ok(key) = u32::from_str_radix(&prefix, 16)
            {
                self.extra.insert(key, name.to_owned());
            }
        }
        self.extra.len() - before
    }

    /// The manufacturer of a hardware address, if it is a registered, global address.
    #[must_use]
    pub fn vendor(&self, mac: &Mac) -> Option<String> {
        if is_local(mac) {
            return None;
        }
        let key = u32::from(mac[0]) << 16 | u32::from(mac[1]) << 8 | u32::from(mac[2]);
        self.extra
            .get(&key)
            .cloned()
            .or_else(|| builtin().get(&key).map(|name| (*name).to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_parse_in_every_common_spelling() {
        let mac = [0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6];
        let want = Some(mac);
        for text in [
            "00:1b:63:84:45:e6",
            "0:1b:63:84:45:e6",
            "00-1B-63-84-45-E6",
            "001b638445e6",
        ] {
            assert_eq!(parse_mac(text), want, "{text}");
        }
        for text in [
            "",
            "00:1b:63",
            "00:1b:63:84:45:e6:ff",
            "gg:1b:63:84:45:e6",
            "001b6384",
        ] {
            assert_eq!(parse_mac(text), None, "{text}");
        }
        assert_eq!(format_mac(&mac), "00:1b:63:84:45:e6");
    }

    #[test]
    fn the_registry_names_real_vendors_and_skips_private_addresses() {
        let oui = Oui::new();
        assert_eq!(
            oui.vendor(&[0xb8, 0x27, 0xeb, 1, 2, 3]).as_deref(),
            Some("Raspberry Pi Foundation")
        );
        assert!(
            oui.vendor(&[0x3c, 0xa6, 0x2f, 1, 2, 3])
                .unwrap()
                .starts_with("AVM")
        );
        assert_eq!(
            oui.vendor(&[0xba, 0x27, 0xeb, 1, 2, 3]),
            None,
            "locally administered"
        );
        assert!(is_local(&[0x02, 0, 0, 0, 0, 1]));
        assert!(
            !is_usable(&[0xff; 6]) && !is_usable(&[0; 6]) && !is_usable(&[0x01, 0, 0x5e, 0, 0, 1])
        );
    }

    #[test]
    fn a_custom_list_adds_and_overrides() {
        let mut oui = Oui::new();
        let read = oui.load("B8-27-EB   (hex)\t\tMy Pi Vendor\nnot a line\n103456\tTab Form Inc\n");
        assert_eq!(read, 2);
        assert_eq!(
            oui.vendor(&[0xb8, 0x27, 0xeb, 0, 0, 0]).as_deref(),
            Some("My Pi Vendor")
        );
        assert_eq!(
            oui.vendor(&[0x10, 0x34, 0x56, 0, 0, 0]).as_deref(),
            Some("Tab Form Inc")
        );
    }
}
