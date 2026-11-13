//! Names and records between the `.local` side and the unicast domain.

use hickory_proto::rr::{Name, RData, Record, rdata::SRV};

/// Maps `<anything>.<domain>` to `<anything>.local` and back.
#[derive(Clone, Debug)]
pub struct Mapper {
    domain: Name,
    local: Name,
}

fn labels(name: &Name) -> Vec<Vec<u8>> {
    name.iter().map(<[u8]>::to_vec).collect()
}

fn rebase(name: &Name, from: &Name, to: &Name) -> Option<Name> {
    if !from.zone_of(name) {
        return None;
    }
    let keep = name.num_labels().checked_sub(from.num_labels())?;
    let mut parts = labels(name);
    parts.truncate(usize::from(keep));
    let relative = Name::from_labels(parts).ok()?;
    relative.append_domain(to).ok()
}

impl Mapper {
    /// `domain` is written without a trailing dot, such as `mdns.home.example`.
    ///
    /// # Errors
    /// The domain is not a valid DNS name.
    pub fn new(domain: &str) -> Result<Self, String> {
        let domain = Name::from_ascii(format!("{}.", domain.trim_end_matches('.')))
            .map_err(|_| "invalid mdns domain")?
            .to_lowercase();
        Ok(Self {
            domain,
            local: Name::from_ascii("local.").map_err(|_| "invalid name")?,
        })
    }

    #[must_use]
    pub fn domain(&self) -> &Name {
        &self.domain
    }

    /// The `.local` name for a name under the domain.
    #[must_use]
    pub fn to_local(&self, name: &Name) -> Option<Name> {
        rebase(&name.to_lowercase(), &self.domain, &self.local)
    }

    /// The domain name for a `.local` name; other names are returned as they are.
    #[must_use]
    pub fn to_domain(&self, name: &Name) -> Name {
        rebase(name, &self.local, &self.domain).unwrap_or_else(|| name.clone())
    }

    /// Whether `name` is the domain itself.
    #[must_use]
    pub fn is_apex(&self, name: &Name) -> bool {
        name.to_lowercase() == self.domain
    }

    /// Whether `name` is the domain or below it.
    #[must_use]
    pub fn handles(&self, name: &Name) -> bool {
        self.domain.zone_of(&name.to_lowercase())
    }

    /// A record as the unicast side should see it: owner and any target name moved to the
    /// domain, and the TTL capped.
    #[must_use]
    pub fn record_to_domain(&self, record: &Record, ttl_cap: u32) -> Record {
        let mut out = record.clone();
        out.name = self.to_domain(&record.name);
        out.ttl = record.ttl.min(ttl_cap);
        out.data = match &record.data {
            RData::PTR(ptr) => RData::PTR(hickory_proto::rr::rdata::PTR(self.to_domain(&ptr.0))),
            RData::CNAME(cname) => {
                RData::CNAME(hickory_proto::rr::rdata::CNAME(self.to_domain(&cname.0)))
            }
            RData::SRV(srv) => RData::SRV(SRV::new(
                srv.priority,
                srv.weight,
                srv.port,
                self.to_domain(&srv.target),
            )),
            other => other.clone(),
        };
        // The cache-flush bit is a multicast detail.
        out.mdns_cache_flush = false;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn names_move_between_local_and_the_domain_in_both_directions() {
        let mapper = Mapper::new("mdns.home.example").unwrap();
        assert_eq!(
            mapper.to_local(&name("Printer.mdns.home.example.")),
            Some(name("printer.local."))
        );
        assert_eq!(
            mapper.to_local(&name("mdns.home.example.")),
            Some(name("local."))
        );
        assert_eq!(mapper.to_local(&name("printer.other.example.")), None);
        assert_eq!(
            mapper.to_domain(&name("a.b._http._tcp.local.")),
            name("a.b._http._tcp.mdns.home.example.")
        );
        assert_eq!(
            mapper.to_domain(&name("example.com.")),
            name("example.com.")
        );
        assert!(mapper.handles(&name("x.mdns.home.example.")));
        assert!(!mapper.handles(&name("home.example.")));
        assert!(mapper.is_apex(&name("MDNS.home.example.")));
        // A label with a dot or a space survives, as service instance names often have.
        let odd = Name::from_labels(vec![
            b"Living Room.TV".to_vec(),
            b"_airplay".to_vec(),
            b"_tcp".to_vec(),
            b"local".to_vec(),
        ])
        .unwrap();
        let moved = mapper.to_domain(&odd);
        assert_eq!(
            mapper.to_local(&moved).unwrap().to_lowercase(),
            odd.to_lowercase()
        );
    }

    #[test]
    fn targets_are_rewritten_ttls_capped_and_the_flush_bit_dropped() {
        let mapper = Mapper::new("mdns.example").unwrap();
        let mut ptr = Record::from_rdata(
            name("_http._tcp.local."),
            4500,
            RData::PTR(PTR(name("web._http._tcp.local."))),
        );
        ptr.mdns_cache_flush = true;
        let out = mapper.record_to_domain(&ptr, 120);
        assert_eq!(out.name, name("_http._tcp.mdns.example."));
        assert_eq!(out.ttl, 120);
        assert!(!out.mdns_cache_flush);
        let RData::PTR(target) = &out.data else {
            panic!("not a PTR")
        };
        assert_eq!(target.0, name("web._http._tcp.mdns.example."));
        let srv = Record::from_rdata(
            name("web._http._tcp.local."),
            120,
            RData::SRV(SRV::new(0, 0, 80, name("host.local."))),
        );
        let RData::SRV(moved) = mapper.record_to_domain(&srv, 3600).data else {
            panic!("not an SRV")
        };
        assert_eq!(&moved.target, &name("host.mdns.example."));
        assert_eq!(moved.port, 80);
        // Addresses pass through unchanged.
        let a = Record::from_rdata(name("host.local."), 10, RData::A(A::new(192, 0, 2, 5)));
        assert_eq!(mapper.record_to_domain(&a, 120).data, a.data);
    }
}
