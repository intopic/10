//! Keccak Fiat–Shamir transcript over 32-byte EVM words, replayable by a
//! Solidity verifier with `keccak256(abi.encodePacked(...))`.
//!
//! `absorb(words)`:  `state ← keccak(0 ‖ state ‖ words)`
//! `challenge()`:    `state ← keccak(1 ‖ state)`, output `state mod r`.

use crate::{point_words, word, Word};
use alloc::vec::Vec;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::PrimeField;
use decider_zk::sumcheck::FsTranscript;
use sha3::{Digest, Keccak256};

#[derive(Clone)]
pub struct KeccakTranscript {
    state: Word,
}

fn tag(t: u8) -> Word {
    let mut w = [0u8; 32];
    w[31] = t;
    w
}

impl KeccakTranscript {
    pub fn new(domain: &[u8]) -> Self {
        Self {
            state: Keccak256::digest(domain).into(),
        }
    }

    pub fn absorb_words(&mut self, words: &[Word]) {
        let mut h = Keccak256::new();
        h.update(tag(0));
        h.update(self.state);
        for w in words {
            h.update(w);
        }
        self.state = h.finalize().into();
    }

    pub fn absorb_scalars(&mut self, values: &[Fr]) {
        let words: Vec<Word> = values.iter().map(word).collect();
        self.absorb_words(&words);
    }

    pub fn absorb_points(&mut self, points: &[G1]) {
        let words: Vec<Word> = points.iter().flat_map(point_words).collect();
        self.absorb_words(&words);
    }

    pub fn challenge(&mut self) -> Fr {
        let mut h = Keccak256::new();
        h.update(tag(1));
        h.update(self.state);
        self.state = h.finalize().into();
        Fr::from_be_bytes_mod_order(&self.state)
    }

    pub fn challenges(&mut self, n: usize) -> Vec<Fr> {
        (0..n).map(|_| self.challenge()).collect()
    }
}

impl FsTranscript<Fr> for KeccakTranscript {
    fn absorb_scalars(&mut self, _label: &'static [u8], values: &[Fr]) {
        KeccakTranscript::absorb_scalars(self, values);
    }
    fn challenge_scalar(&mut self) -> Fr {
        self.challenge()
    }
}
