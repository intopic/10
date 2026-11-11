//! Minimal Solidity ABI encoding for the calls of `ZenoLlullVerifier`.

use crate::{point_words, word, MaskProof, StepProof, Word};
use alloc::vec::Vec;
use ark_bn254::Fr;
use sha3::{Digest, Keccak256};

/// The 4-byte selector of a function signature.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn uint(v: usize) -> Word {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&(v as u64).to_be_bytes());
    out
}

/// Tail encoding of `bytes`: length, then data padded to a word boundary.
fn bytes_tail(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(uint(data.len()));
    out.extend_from_slice(data);
    out.resize(out.len() + (32 - data.len() % 32) % 32, 0);
}

fn words_tail(out: &mut Vec<u8>, words: &[Fr]) {
    out.extend(uint(words.len()));
    for w in words {
        out.extend(word(w));
    }
}

/// `openSession(bytes32 vk, uint256[] z0)`.
pub fn open_session(vk: &Word, z0: &[Fr]) -> Vec<u8> {
    let mut out = selector("openSession(bytes32,uint256[])").to_vec();
    out.extend(vk);
    out.extend(uint(0x40));
    words_tail(&mut out, z0);
    out
}

/// `verifyFoldedProof(bytes proof, uint256[] publicInputs)` with
/// `proof = sessionId ‖ comm_W ‖ comm_T` (160 bytes).
pub fn verify_folded_proof(session: &Word, step: &StepProof) -> Vec<u8> {
    let mut proof = session.to_vec();
    for w in point_words(&step.comm_w)
        .iter()
        .chain(&point_words(&step.comm_t))
    {
        proof.extend(w);
    }
    let mut out = selector("verifyFoldedProof(bytes,uint256[])").to_vec();
    let proof_words = proof.len().div_ceil(32);
    out.extend(uint(0x40));
    out.extend(uint(0x40 + 32 + 32 * proof_words));
    bytes_tail(&mut out, &proof);
    words_tail(&mut out, &step.public_inputs);
    out
}

/// `finalize(bytes32 sessionId, bytes maskProof)` with
/// `maskProof = comm_E ‖ u ‖ comm_W ‖ x ‖ comm_T`.
pub fn finalize(session: &Word, mask: &MaskProof) -> Vec<u8> {
    let mut proof = Vec::new();
    for w in point_words(&mask.mask.comm_e) {
        proof.extend(w);
    }
    proof.extend(word(&mask.mask.u));
    for w in point_words(&mask.mask.comm_w) {
        proof.extend(w);
    }
    for x in &mask.mask.x {
        proof.extend(word(x));
    }
    for w in point_words(&mask.comm_t) {
        proof.extend(w);
    }
    let mut out = selector("finalize(bytes32,bytes)").to_vec();
    out.extend(session);
    out.extend(uint(0x40));
    bytes_tail(&mut out, &proof);
    out
}

/// `getAccumulator(bytes32 sessionId)`.
pub fn get_accumulator(session: &Word) -> Vec<u8> {
    let mut out = selector("getAccumulator(bytes32)").to_vec();
    out.extend(session);
    out
}
