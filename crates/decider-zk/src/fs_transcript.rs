//! A SHA-256 Fiat–Shamir transcript for the final (non-recursive) SNARK.

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// Hash-chain transcript: every absorbed message updates a 32-byte state.
#[derive(Clone)]
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(domain: &[u8]) -> Self {
        let mut t = Self { state: [0; 32] };
        t.absorb_bytes(b"domain", domain);
        t
    }

    pub fn absorb_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        self.state = h.finalize().into();
    }

    /// Absorbs any canonically serializable value (field elements, points…).
    pub fn absorb(&mut self, label: &[u8], value: &impl CanonicalSerialize) {
        let mut bytes = Vec::new();
        value
            .serialize_compressed(&mut bytes)
            .expect("serializing to a Vec cannot fail");
        self.absorb_bytes(label, &bytes);
    }

    /// Squeezes a field element with negligible bias (512 bits reduced mod p).
    pub fn challenge<F: PrimeField>(&mut self) -> F {
        let mut wide = [0u8; 64];
        for (i, chunk) in wide.chunks_mut(32).enumerate() {
            let mut h = Sha256::new();
            h.update(self.state);
            h.update(b"challenge");
            h.update([i as u8]);
            chunk.copy_from_slice(&h.finalize());
        }
        self.absorb_bytes(b"squeezed", &[]);
        F::from_le_bytes_mod_order(&wide)
    }

    /// Squeezes a 128-bit challenge: enough for soundness and twice as
    /// cheap to multiply curve points by.
    pub fn challenge_128<F: PrimeField>(&mut self) -> F {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update(b"challenge-128");
        let digest = h.finalize();
        self.absorb_bytes(b"squeezed", &[]);
        F::from_le_bytes_mod_order(&digest[..16])
    }

    pub fn challenges<F: PrimeField>(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.challenge()).collect()
    }
}
