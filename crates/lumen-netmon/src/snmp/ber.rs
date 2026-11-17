//! The small part of ASN.1 BER that SNMP uses, with strict bounds: depth, length and count limits
//! keep a hostile or broken device from making the decoder allocate or loop.

use std::fmt;

/// Longest message the decoder reads.
pub const MAX_MESSAGE: usize = 65_535;
const MAX_DEPTH: usize = 8;

/// An object identifier.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// `1.3.6.1.2.1.1.1.0`, with or without a leading dot.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let parts: Option<Vec<u32>> = text
            .trim_start_matches('.')
            .split('.')
            .map(|p| p.parse().ok())
            .collect();
        parts.filter(|p| p.len() >= 2 && p.len() <= 128).map(Self)
    }

    /// This OID with one more arc.
    #[must_use]
    pub fn child(&self, arc: u32) -> Self {
        let mut next = self.0.clone();
        next.push(arc);
        Self(next)
    }

    #[must_use]
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// The arcs after `prefix`, when this OID starts with it.
    #[must_use]
    pub fn suffix(&self, prefix: &Oid) -> Option<&[u32]> {
        self.0.strip_prefix(prefix.0.as_slice())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: Vec<String> = self.0.iter().map(u32::to_string).collect();
        write!(f, "{}", text.join("."))
    }
}

/// A value in a variable binding.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Integer(i64),
    Text(Vec<u8>),
    Null,
    Oid(Oid),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    /// Any numeric value as an unsigned integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Integer(v) => u64::try_from(*v).ok(),
            Self::Counter32(v) | Self::Gauge32(v) | Self::TimeTicks(v) => Some(u64::from(*v)),
            Self::Counter64(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            other => other.as_u64().and_then(|v| i64::try_from(v).ok()),
        }
    }

    /// Text, with anything that is not printable text rejected.
    #[must_use]
    pub fn as_text(&self) -> Option<String> {
        match self {
            Self::Text(bytes) => {
                let text = String::from_utf8_lossy(bytes);
                let text: String = text.chars().filter(|c| !c.is_control()).take(512).collect();
                Some(text.trim().to_owned())
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(b) | Self::Opaque(b) => Some(b),
            _ => None,
        }
    }

    /// The row does not exist (a missing object, or the end of the tree).
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(
            self,
            Self::NoSuchObject | Self::NoSuchInstance | Self::EndOfMibView
        )
    }
}

// ---- tags ----
pub const INTEGER: u8 = 0x02;
pub const OCTETS: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OBJECT_ID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const IP_ADDRESS: u8 = 0x40;
pub const COUNTER32: u8 = 0x41;
pub const GAUGE32: u8 = 0x42;
pub const TIME_TICKS: u8 = 0x43;
pub const OPAQUE: u8 = 0x44;
pub const COUNTER64: u8 = 0x46;
pub const NO_SUCH_OBJECT: u8 = 0x80;
pub const NO_SUCH_INSTANCE: u8 = 0x81;
pub const END_OF_MIB_VIEW: u8 = 0x82;
pub const GET_REQUEST: u8 = 0xa0;
pub const GET_NEXT_REQUEST: u8 = 0xa1;
pub const RESPONSE: u8 = 0xa2;
pub const GET_BULK_REQUEST: u8 = 0xa5;
pub const REPORT: u8 = 0xa8;

// ---- writing ----

fn length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, u8::try_from(len).unwrap_or(0)]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    }
}

/// A tag, a length, and the contents.
#[must_use]
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 4);
    out.push(tag);
    length(contents.len(), &mut out);
    out.extend_from_slice(contents);
    out
}

#[must_use]
pub fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(INTEGER, &bytes[start..])
}

#[must_use]
pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(OCTETS, bytes)
}

#[must_use]
pub fn oid(value: &Oid) -> Vec<u8> {
    let arcs = &value.0;
    let mut body = Vec::new();
    let first = arcs.first().copied().unwrap_or(0);
    let second = arcs.get(1).copied().unwrap_or(0);
    let push = |mut arc: u32, body: &mut Vec<u8>| {
        let mut chunk = [0u8; 5];
        let mut n = 0;
        loop {
            chunk[n] = (arc & 0x7f) as u8;
            arc >>= 7;
            n += 1;
            if arc == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            body.push(chunk[i] | if i == 0 { 0 } else { 0x80 });
        }
    };
    push(first * 40 + second, &mut body);
    for arc in arcs.iter().skip(2) {
        push(*arc, &mut body);
    }
    tlv(OBJECT_ID, &body)
}

#[must_use]
pub fn null() -> Vec<u8> {
    tlv(NULL, &[])
}

#[must_use]
pub fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &items.concat())
}

// ---- reading ----

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad SNMP message: {}", self.0)
    }
}

/// A cursor over BER data.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    depth: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, depth: 0 }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The next element: its tag and a reader over its contents.
    ///
    /// # Errors
    /// The data is truncated, too long, or nested too deeply.
    #[allow(clippy::should_implement_trait)] // It returns a Result, not an Option.
    pub fn next(&mut self) -> Result<(u8, Reader<'a>), DecodeError> {
        let (&tag, rest) = self.data.split_first().ok_or(DecodeError("truncated"))?;
        let (&first, rest) = rest.split_first().ok_or(DecodeError("truncated"))?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 2 || rest.len() < count {
                return Err(DecodeError("bad length"));
            }
            let len = rest[..count]
                .iter()
                .fold(0usize, |acc, b| acc << 8 | usize::from(*b));
            (len, &rest[count..])
        };
        if len > rest.len() || len > MAX_MESSAGE {
            return Err(DecodeError("length past the end"));
        }
        if self.depth >= MAX_DEPTH {
            return Err(DecodeError("nested too deeply"));
        }
        self.data = &rest[len..];
        Ok((
            tag,
            Reader {
                data: &rest[..len],
                depth: self.depth + 1,
            },
        ))
    }

    /// The element's bytes, after checking its tag.
    ///
    /// # Errors
    /// The next element has another tag.
    pub fn expect(&mut self, tag: u8) -> Result<Reader<'a>, DecodeError> {
        let (found, inner) = self.next()?;
        if found == tag {
            Ok(inner)
        } else {
            Err(DecodeError("unexpected element"))
        }
    }

    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// # Errors
    /// The next element is not an integer.
    pub fn read_integer(&mut self) -> Result<i64, DecodeError> {
        let inner = self.expect(INTEGER)?;
        parse_int(inner.data)
    }

    /// # Errors
    /// The next element is not an octet string.
    pub fn read_octets(&mut self) -> Result<&'a [u8], DecodeError> {
        Ok(self.expect(OCTETS)?.data)
    }
}

fn parse_int(data: &[u8]) -> Result<i64, DecodeError> {
    if data.is_empty() || data.len() > 9 {
        return Err(DecodeError("bad integer"));
    }
    let mut value: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for b in data {
        value = value
            .checked_shl(8)
            .ok_or(DecodeError("integer too large"))?
            | i64::from(*b);
    }
    Ok(value)
}

fn parse_unsigned(data: &[u8]) -> Result<u64, DecodeError> {
    let data = if data.first() == Some(&0) {
        &data[1..]
    } else {
        data
    };
    if data.len() > 8 {
        return Err(DecodeError("counter too large"));
    }
    Ok(data.iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b)))
}

/// # Errors
/// The contents are not a valid object identifier.
pub fn parse_oid(data: &[u8]) -> Result<Oid, DecodeError> {
    if data.is_empty() || data.len() > 160 {
        return Err(DecodeError("bad object identifier"));
    }
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for (i, byte) in data.iter().enumerate() {
        value = value << 7 | u64::from(byte & 0x7f);
        if value > u64::from(u32::MAX) * 40 + 80 {
            return Err(DecodeError("object identifier arc too large"));
        }
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b) = if value < 40 {
                    (0, value)
                } else if value < 80 {
                    (1, value - 40)
                } else {
                    (2, value - 80)
                };
                arcs.push(a);
                arcs.push(u32::try_from(b).map_err(|_| DecodeError("arc too large"))?);
            } else {
                arcs.push(u32::try_from(value).map_err(|_| DecodeError("arc too large"))?);
            }
            value = 0;
        } else if i + 1 == data.len() {
            return Err(DecodeError("truncated object identifier"));
        }
    }
    Ok(Oid(arcs))
}

/// Read one value of a variable binding.
///
/// # Errors
/// The element is not a known SNMP value or is malformed.
pub fn read_value(reader: &mut Reader<'_>) -> Result<Value, DecodeError> {
    let (tag, inner) = reader.next()?;
    let data = inner.data;
    Ok(match tag {
        INTEGER => Value::Integer(parse_int(data)?),
        OCTETS => Value::Text(data.to_vec()),
        NULL => Value::Null,
        OBJECT_ID => Value::Oid(parse_oid(data)?),
        IP_ADDRESS => Value::IpAddress(data.try_into().map_err(|_| DecodeError("bad address"))?),
        COUNTER32 => Value::Counter32(
            u32::try_from(parse_unsigned(data)?).map_err(|_| DecodeError("counter too large"))?,
        ),
        GAUGE32 => Value::Gauge32(
            u32::try_from(parse_unsigned(data)?).map_err(|_| DecodeError("gauge too large"))?,
        ),
        TIME_TICKS => Value::TimeTicks(
            u32::try_from(parse_unsigned(data)?).map_err(|_| DecodeError("ticks too large"))?,
        ),
        OPAQUE => Value::Opaque(data.to_vec()),
        COUNTER64 => Value::Counter64(parse_unsigned(data)?),
        NO_SUCH_OBJECT => Value::NoSuchObject,
        NO_SUCH_INSTANCE => Value::NoSuchInstance,
        END_OF_MIB_VIEW => Value::EndOfMibView,
        _ => return Err(DecodeError("unknown value type")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_use_the_shortest_twos_complement_form() {
        assert_eq!(integer(0), [2, 1, 0]);
        assert_eq!(integer(127), [2, 1, 127]);
        assert_eq!(integer(128), [2, 2, 0, 128]);
        assert_eq!(integer(-1), [2, 1, 0xff]);
        assert_eq!(integer(-129), [2, 2, 0xff, 0x7f]);
        for v in [
            0,
            1,
            -1,
            127,
            128,
            255,
            256,
            -128,
            -129,
            65_535,
            2_147_483_647,
            -2_147_483_648,
            i64::MAX,
            i64::MIN,
        ] {
            let bytes = integer(v);
            assert_eq!(Reader::new(&bytes).read_integer().unwrap(), v, "{v}");
        }
    }

    #[test]
    fn object_identifiers_round_trip_including_large_arcs() {
        let o = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid(&o), [6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0]);
        for text in [
            "1.3.6.1.4.1.2021.11.11.0",
            "1.3.6.1.2.1.31.1.1.1.6.4294967295",
            "2.100.3",
            "0.0",
        ] {
            let o = Oid::parse(text).unwrap();
            let bytes = oid(&o);
            let mut r = Reader::new(&bytes);
            let inner = r.expect(OBJECT_ID).unwrap();
            assert_eq!(parse_oid(inner.bytes()).unwrap().to_string(), text);
        }
        assert!(
            Oid::parse("1").is_none() && Oid::parse("a.b").is_none() && Oid::parse("").is_none()
        );
        let a = Oid::parse("1.3.6.1.2.1.2.2.1.2").unwrap();
        assert_eq!(a.child(5).suffix(&a), Some(&[5u32][..]));
    }

    #[test]
    fn lengths_use_the_long_form_and_values_decode() {
        let long = tlv(OCTETS, &[7u8; 300]);
        assert_eq!(&long[..4], [4, 0x82, 0x01, 0x2c]);
        assert_eq!(Reader::new(&long).read_octets().unwrap().len(), 300);
        let mut r = Reader::new(&[0x41, 0x04, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(read_value(&mut r).unwrap(), Value::Counter32(u32::MAX));
        let mut r = Reader::new(&[
            0x46, 0x09, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        assert_eq!(read_value(&mut r).unwrap(), Value::Counter64(u64::MAX));
        let mut r = Reader::new(&[0x82, 0]);
        assert!(read_value(&mut r).unwrap().is_missing());
        assert_eq!(
            Value::Text(b"ro\x00ut\x07er".to_vec()).as_text().as_deref(),
            Some("router")
        );
    }

    #[test]
    fn malformed_input_is_refused_not_trusted() {
        for bad in [
            &[][..],
            &[0x30][..],
            &[0x30, 0x05, 0x02][..],
            &[0x30, 0x84, 1, 0, 0, 0][..],
            &[0x02, 0x00][..],
            &[0x06, 0x02, 0x2b, 0x86][..],
            &[0x30, 0x80][..],
        ] {
            let mut r = Reader::new(bad);
            let outcome = r.next().and_then(|(tag, mut inner)| match tag {
                INTEGER => inner.next().map(|_| ()),
                OBJECT_ID => parse_oid(inner.bytes()).map(|_| ()),
                _ => Ok(()),
            });
            let mut r2 = Reader::new(bad);
            let value = read_value(&mut r2);
            assert!(outcome.is_err() || value.is_err(), "{bad:?}");
        }
        // Deep nesting stops.
        let mut deep = vec![0x05, 0];
        for _ in 0..20 {
            deep = tlv(SEQUENCE, &deep);
        }
        let mut r = Reader::new(&deep);
        let mut depth = 0;
        let mut cur = r.next();
        while let Ok((_, mut inner)) = cur {
            depth += 1;
            cur = inner.next();
        }
        assert!(depth <= MAX_DEPTH + 1, "{depth}");
    }
}
