//! Minimal Solidity ABI encoding for the calls of `ZenoLlullVerifier`.

use crate::{point_words, word, EvmParams, MaskProof, OnChainDeciderProof, StepProof, Word};
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::VerifyingKey;
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

fn mask_bytes(mask: &MaskProof) -> Vec<u8> {
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
    proof
}

/// `finalize(bytes32 sessionId, bytes maskProof)` with
/// `maskProof = comm_E ‖ u ‖ comm_W ‖ x ‖ comm_T`.
pub fn finalize(session: &Word, mask: &MaskProof) -> Vec<u8> {
    let mut out = selector("finalize(bytes32,bytes)").to_vec();
    out.extend(session);
    out.extend(uint(0x40));
    bytes_tail(&mut out, &mask_bytes(mask));
    out
}

fn g1_words(p: &G1Affine) -> [Word; 2] {
    match p.xy() {
        Some((x, y)) => [word(&x), word(&y)],
        None => [[0u8; 32]; 2],
    }
}

/// A G2 point in the pairing precompile's order: `x.c1, x.c0, y.c1, y.c0`.
fn g2_words(p: &G2Affine) -> [Word; 4] {
    match p.xy() {
        Some((x, y)) => [word(&x.c1), word(&x.c0), word(&y.c1), word(&y.c0)],
        None => [word(&Fq::from(0u64)); 4],
    }
}

/// The decider key passed to `finalizeWithProof`:
/// `[H, [τ]₂, α, β, γ, δ, IC…]`. Panics if `params` is not a KZG setup.
pub fn decider_key(params: &EvmParams, vk: &VerifyingKey<Bn254>) -> Vec<Word> {
    let tau_g2 = params.tau_g2.expect("decider key needs KZG parameters");
    let mut words = Vec::new();
    words.extend(g1_words(&params.ck.h));
    words.extend(g2_words(&tau_g2));
    words.extend(g1_words(&vk.alpha_g1));
    words.extend(g2_words(&vk.beta_g2));
    words.extend(g2_words(&vk.gamma_g2));
    words.extend(g2_words(&vk.delta_g2));
    for ic in &vk.gamma_abc_g1 {
        words.extend(g1_words(ic));
    }
    words
}

/// `registerCircuit(bytes32 vk, bytes32 keyHash)`.
pub fn register_circuit(vk: &Word, key: &[Word]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    for w in key {
        hasher.update(w);
    }
    let mut out = selector("registerCircuit(bytes32,bytes32)").to_vec();
    out.extend(vk);
    out.extend(hasher.finalize());
    out
}

/// The 17 proof words of `finalizeWithProof`:
/// `[W(c), E(c), r_W, r_E, π_W, π_E, A, B, C, d]`.
pub fn decider_proof_words(proof: &OnChainDeciderProof) -> Vec<Word> {
    let mut words = alloc::vec![
        word(&proof.w_eval),
        word(&proof.e_eval),
        word(&proof.r_w),
        word(&proof.r_e),
    ];
    words.extend(point_words(&proof.pi_w));
    words.extend(point_words(&proof.pi_e));
    words.extend(g1_words(&proof.groth16.a));
    words.extend(g2_words(&proof.groth16.b));
    words.extend(g1_words(&proof.groth16.c));
    words.push(word(&proof.digest));
    words
}

/// `finalizeWithProof(bytes32 sessionId, bytes maskProof, uint256[17] proof, uint256[] key)`.
pub fn finalize_with_proof(
    session: &Word,
    mask: &MaskProof,
    proof: &OnChainDeciderProof,
    key: &[Word],
) -> Vec<u8> {
    let mask = mask_bytes(mask);
    let head = 32 * (1 + 1 + 17 + 1);
    let mut out = selector("finalizeWithProof(bytes32,bytes,uint256[17],uint256[])").to_vec();
    out.extend(session);
    out.extend(uint(head));
    for w in decider_proof_words(proof) {
        out.extend(w);
    }
    out.extend(uint(head + 32 + 32 * mask.len().div_ceil(32)));
    bytes_tail(&mut out, &mask);
    out.extend(uint(key.len()));
    for w in key {
        out.extend(w);
    }
    out
}

/// `getAccumulator(bytes32 sessionId)`.
pub fn get_accumulator(session: &Word) -> Vec<u8> {
    let mut out = selector("getAccumulator(bytes32)").to_vec();
    out.extend(session);
    out
}
