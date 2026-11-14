//! Length checks of serialized data *before* it is deserialized.
//!
//! `ark-serialize` reads the length of a `Vec` from the input and reserves
//! that much memory before reading a single element, so eight hostile bytes
//! can make a verifier abort on a multi-terabyte allocation. Every format
//! that untrusted parties hand to us (proofs, saved prover states) is
//! therefore first walked with its layout: the declared lengths must add up
//! to exactly the input length.

/// One serialized item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    /// A fixed-size item of this many bytes (a field element, a point, an
    /// integer).
    Fixed(usize),
    /// A `Vec` of fixed-size items of this many bytes each: a little-endian
    /// `u64` length, then the items.
    Vec(usize),
}

/// Whether `bytes` is exactly a sequence of `items`, every declared length
/// included. Allocates nothing.
pub fn fits(bytes: &[u8], items: &[Item]) -> bool {
    let mut at = 0usize;
    for item in items {
        let next = match *item {
            Item::Fixed(size) => at.checked_add(size),
            Item::Vec(size) => {
                let Some(len) = at.checked_add(8).and_then(|end| bytes.get(at..end)) else {
                    return false;
                };
                let len = u64::from_le_bytes(len.try_into().expect("8 bytes"));
                usize::try_from(len)
                    .ok()
                    .and_then(|len| len.checked_mul(size))
                    .and_then(|body| body.checked_add(8))
                    .and_then(|body| at.checked_add(body))
            }
        };
        match next {
            Some(next) if next <= bytes.len() => at = next,
            _ => return false,
        }
    }
    at == bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_of(len: u64, size: usize) -> alloc::vec::Vec<u8> {
        let mut out = len.to_le_bytes().to_vec();
        out.resize(8 + len as usize * size, 7);
        out
    }

    #[test]
    fn declared_lengths_must_match_the_input() {
        let items = [Item::Fixed(8), Item::Vec(32), Item::Fixed(32)];
        let mut ok = [0u8; 8].to_vec();
        ok.extend(vec_of(3, 32));
        ok.extend([1u8; 32]);
        assert!(fits(&ok, &items));
        // One byte short, one byte too many.
        assert!(!fits(&ok[..ok.len() - 1], &items));
        let mut long = ok.clone();
        long.push(0);
        assert!(!fits(&long, &items));
        // A hostile length: refused without allocating.
        let mut huge = [0u8; 8].to_vec();
        huge.extend(u64::MAX.to_le_bytes());
        huge.extend([0u8; 64]);
        assert!(!fits(&huge, &items));
        let mut big = [0u8; 8].to_vec();
        big.extend((1u64 << 40).to_le_bytes());
        assert!(!fits(&big, &items));
        assert!(!fits(&[], &items));
    }
}
