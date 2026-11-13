//! The EVM decider of the recursive (CycleFold) IVC: one proof for `N` steps,
//! independent of `N`, checked by `finalizeRecursive`.
//!
//! The final IVC state is `(i, z_0, z_i, U, u, U_cf)`: the primary
//! accumulator `U` and the last primary instance `u` (KZG commitments on
//! BN254), and the CycleFold accumulator `U_cf` (Hyrax rows on Grumpkin).
//! One Keccak transcript drives everything:
//!
//! 1. `u` is folded into `U` and the result is masked by folding in a random
//!    satisfying relaxed instance (zero knowledge for the application's
//!    witness), both with on-chain NIFS folds; the result is decided by the
//!    universal decider for the primary circuit.
//! 2. `U_cf` is decided by a Spartan-style argument over `Fq` (native for the
//!    EVM's `mulmod`): an outer and an inner sum-check, with the matrices of
//!    the CycleFold circuit (fixed for the whole system, published as a data
//!    contract) evaluated by the verifier. What remains are the evaluations
//!    `Ẽ(r_x)` and `W̃(r_y')`, opened by the Hyrax rows: the prover sends the
//!    combined rows `e'` and `w'`, the verifier checks their inner products,
//!    and the group equation `Σ_i s_i·C_i = Σ_j c_j·G_j` is left to
//! 3. the closing circuit ([`zeno_ivc::cyclefold::closing`]), whose public
//!    input the verifier assembles itself; it also recomputes the state hash
//!    `h = H(vk, i, z_0, z_i, U, U_cf) = u.x`. Its instance is decided by the
//!    universal decider for the closing circuit.
//! 4. The masked primary accumulator and the closing instance are decided by
//!    one batched universal proof ([`universal::batch`]): both circuit keys
//!    share the same dimensions, so one set of sum-checks and one joint
//!    opening cover both, with one pairing check.

use crate::{
    kzg::Srs,
    point_words, relaxed_words,
    universal::{
        self,
        batch::{self, BatchProof, Item},
        transcript::KeccakTranscript,
        CircuitKey, Dims,
    },
    word, DeciderError, EvmParams, Word,
};
use alloc::{collections::BTreeMap, vec::Vec};
use ark_bn254::{Fq, Fr, G1Projective as G1};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
use ark_std::rand::RngCore;
use core_r1cs::{
    ark_bridge::{assignment_from_cs, shape_from_cs},
    R1CSInstance, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness,
};
use decider_zk::sumcheck;
use llull_folder::{
    fold_instance, fold_relaxed_instance, nifs_prove_relaxed_with, nifs_prove_with,
};
use sha3::{Digest, Keccak256};
use zeno_ivc::{
    cyclefold::{
        augmented::{absorb_cf_acc, absorb_primary},
        closing::ClosingCircuit,
        hyrax::{eq_table, hyrax_open, CfRelaxedInstance, CfRelaxedWitness},
        CycleFoldAccumulator, CycleFoldParams, CF_COLUMNS, CF_IO_LEN,
    },
    gadgets::ec::odd_t,
    IvcError, StepCircuit,
};

pub type Bn254Config = ark_bn254::g1::Config;
pub type GrumpkinConfig = ark_grumpkin::GrumpkinConfig;
type Grumpkin = ark_grumpkin::Projective;

/// Domain separator of the recursive decider's transcript.
pub const DOMAIN: &[u8] = b"zeno-llull/recursive-decider/v1";

fn log2_ceil(v: usize) -> usize {
    v.next_power_of_two().trailing_zeros() as usize
}

/// Dimensions of the Spartan argument over the CycleFold circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CfDims {
    pub log_m: usize,
    pub log_n: usize,
}

impl CfDims {
    pub fn of(shape: &R1CSShape<Fq>) -> Self {
        Self {
            log_m: log2_ceil(shape.num_constraints.max(4)),
            log_n: log2_ceil(shape.num_vars.max(shape.num_io + 1).max(4)),
        }
    }
}

/// Column of `Z = (W, x, u)` inside the padded `(W ‖ (u, x))` of length `2n`.
fn remap(shape: &R1CSShape<Fq>, n: usize, col: usize) -> usize {
    if col < shape.num_vars {
        col
    } else if col == shape.num_vars + shape.num_io {
        n
    } else {
        n + 1 + (col - shape.num_vars)
    }
}

/// One non-zero matrix entry: `(matrix, row, column in the padded Z, value)`.
fn entries(shape: &R1CSShape<Fq>) -> Vec<(usize, usize, usize, Fq)> {
    let n = 1 << CfDims::of(shape).log_n;
    let mut out = Vec::new();
    for (k, m) in [&shape.a, &shape.b, &shape.c].iter().enumerate() {
        for row in 0..m.num_rows {
            for e in m.row_ptr[row]..m.row_ptr[row + 1] {
                out.push((k, row, remap(shape, n, m.col_idx[e]), m.values[e]));
            }
        }
    }
    out.sort_by_key(|&(k, row, col, _)| (row, k, col));
    out
}

/// The CycleFold matrices as the contract reads them (the code of a data
/// contract, after a leading `0x00` that makes it non-executable), laid out
/// so that every entry costs the verifier two loads, one `mulmod` and one
/// `addmod`:
///
/// * a 32-byte header: `log_m`, `log_n`, `num_io` (one byte each), then the
///   numbers of distinct values, of groups and of entries (two bytes each,
///   big-endian);
/// * the distinct values, 32 bytes each (big-endian `Fq`);
/// * the groups, 4 bytes each: `half·128 + matrix (1 byte) ‖ value index
///   (1 byte) ‖ number of entries (2 bytes)` — all entries of one matrix with
///   one value in one half of the padded `Z = (W ‖ (u, x))`;
/// * the entries, group after group, 4 bytes each: `32·row (2 bytes) ‖
///   32·(column mod n) (2 bytes)`, the byte offsets into the tables
///   `eq(r_x, ·)` and `eq(r_y[1..], ·)`.
///
/// The verifier then computes `Σ_groups ρ^matrix·value·(r_y0 or 1 − r_y0)·
/// Σ_entries eq(r_x, row)·eq(r_y[1..], col mod n) = (A + ρB + ρ²C)(r_x, r_y)`.
pub fn cf_matrix_data(shape: &R1CSShape<Fq>) -> Vec<u8> {
    let dims = CfDims::of(shape);
    assert!(
        dims.log_m <= 10 && dims.log_n < 11,
        "CycleFold circuit too large for the encoding"
    );
    let mut index: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut values: Vec<Fq> = Vec::new();
    let n = 1 << dims.log_n;
    let mut groups: BTreeMap<(usize, usize, usize), Vec<(usize, usize)>> = BTreeMap::new();
    for (k, row, col, v) in entries(shape) {
        let key = v.into_bigint().to_bytes_be();
        let idx = *index.entry(key).or_insert_with(|| {
            values.push(v);
            values.len() - 1
        });
        groups
            .entry((col / n, k, idx))
            .or_default()
            .push((row, col % n));
    }
    let num_entries: usize = groups.values().map(Vec::len).sum();
    assert!(
        values.len() <= 256 && groups.len() < 1 << 16 && num_entries < 1 << 16,
        "too many values, groups or entries"
    );
    let mut data = alloc::vec![0u8; 32];
    data[0] = dims.log_m as u8;
    data[1] = dims.log_n as u8;
    data[2] = shape.num_io as u8;
    data[3..5].copy_from_slice(&(values.len() as u16).to_be_bytes());
    data[5..7].copy_from_slice(&(groups.len() as u16).to_be_bytes());
    data[7..9].copy_from_slice(&(num_entries as u16).to_be_bytes());
    for v in &values {
        data.extend_from_slice(&word(v));
    }
    for (&(half, k, idx), list) in &groups {
        data.extend_from_slice(&[(half << 7 | k) as u8, idx as u8]);
        data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    }
    for list in groups.values() {
        for &(row, col) in list {
            data.extend_from_slice(&((32 * row) as u16).to_be_bytes());
            data.extend_from_slice(&((32 * col) as u16).to_be_bytes());
        }
    }
    data
}

/// The data contract's code (`0x00 ‖ data`) and its `extcodehash`.
pub fn cf_data_code(shape: &R1CSShape<Fq>) -> (Vec<u8>, Word) {
    let mut code = alloc::vec![0u8];
    code.extend(cf_matrix_data(shape));
    let hash = Keccak256::digest(&code).into();
    (code, hash)
}

/// Public parameters: the CycleFold IVC, the universal-decider keys of its
/// primary circuit and of the closing circuit (over one reference string),
/// and the hash of the CycleFold matrix data.
pub struct RecursiveParams {
    pub ivc: CycleFoldParams<Bn254Config, GrumpkinConfig>,
    pub primary: EvmParams,
    pub primary_key: CircuitKey,
    pub closing: EvmParams,
    pub closing_key: CircuitKey,
    pub cf_code: Vec<u8>,
    pub cf_code_hash: Word,
}

impl RecursiveParams {
    /// Everything is derived from the step circuit and the reference string;
    /// no per-circuit secret is involved.
    pub fn setup<SC: StepCircuit<Fr>>(
        step: &SC,
        label: &[u8],
        srs: &Srs,
    ) -> Result<Self, IvcError> {
        let primary_label = [label, b"/primary"].concat();
        let ivc = CycleFoldParams::setup_with_key(step, label, CF_COLUMNS, |len| {
            srs.commitment_key(&primary_label, len)
        })?;
        let closing_shape = {
            let (rows_w, rows_e) = ivc.cf_rows();
            let placeholder = ClosingCircuit::<Bn254Config, GrumpkinConfig> {
                poseidon: &ivc.poseidon,
                digest: ivc.digest,
                gens: &ivc.cf_key.ck.gens,
                i: 0,
                z0: alloc::vec![Fr::zero(); ivc.arity],
                zi: alloc::vec![Fr::zero(); ivc.arity],
                acc: RelaxedR1CSInstance::default_for(&ivc.shape),
                cf_acc: CfRelaxedInstance::default_for(&ivc.cf_shape, &ivc.cf_key),
                row_weights: alloc::vec![Fq::zero(); rows_w + rows_e],
                combined: alloc::vec![Fq::zero(); ivc.cf_key.cols()],
            };
            let cs = ConstraintSystem::new_ref();
            cs.set_mode(SynthesisMode::Prove {
                construct_matrices: true,
            });
            placeholder.synthesize(cs.clone())?;
            shape_from_cs(&cs)?
        };
        // Both circuits are decided by one batched argument, so their keys
        // share the larger dimensions of the two.
        let (dp, dc) = (Dims::of(&ivc.shape), Dims::of(&closing_shape));
        let dims = Dims {
            log_m: dp.log_m.max(dc.log_m),
            log_n: dp.log_n.max(dc.log_n),
            log_k: dp.log_k.max(dc.log_k),
        };
        let (primary, primary_key) =
            EvmParams::setup_universal_with_dims(ivc.shape.clone(), &primary_label, srs, dims);
        // The IVC commits with a prefix of the decider's key.
        assert_eq!(primary.ck.h, ivc.ck.h);
        assert_eq!(primary.ck.gens[..ivc.ck.len()], ivc.ck.gens[..]);
        let (closing, closing_key) = EvmParams::setup_universal_with_dims(
            closing_shape,
            &[label, b"/closing"].concat(),
            srs,
            dims,
        );
        let (cf_code, cf_code_hash) = cf_data_code(&ivc.cf_shape);
        Ok(Self {
            ivc,
            primary,
            primary_key,
            closing,
            closing_key,
            cf_code,
            cf_code_hash,
        })
    }

    /// The system's on-chain identity:
    /// `keccak256(primary vk ‖ closing vk ‖ CycleFold data code hash)`.
    pub fn system_id(&self) -> Word {
        let mut h = Keccak256::new();
        h.update(self.primary.vk);
        h.update(self.closing.vk);
        h.update(self.cf_code_hash);
        h.finalize().into()
    }
}

/// The Spartan argument for the CycleFold accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfProof {
    pub outer: Vec<Fq>,
    /// `(Az)(r_x), (Bz)(r_x), (Cz)(r_x), E(r_x)`.
    pub claims: [Fq; 4],
    pub inner: Vec<Fq>,
    /// `W̃(r_y[1..])`.
    pub v_w: Fq,
    /// The combined Hyrax rows `e' = Σ L_E,i·E_i` and `w' = Σ L_W,i·W_i`.
    pub e_row: Vec<Fq>,
    pub w_row: Vec<Fq>,
}

/// Everything `finalizeRecursive` receives besides the keys.
#[derive(Clone, Debug)]
pub struct RecursiveProof {
    pub i: u64,
    pub z0: Vec<Fr>,
    pub zi: Vec<Fr>,
    pub acc: RelaxedR1CSInstance<G1>,
    pub last: R1CSInstance<G1>,
    pub comm_t: G1,
    pub mask: RelaxedR1CSInstance<G1>,
    pub mask_t: G1,
    pub cf_acc: CfRelaxedInstance<Grumpkin>,
    pub cf: CfProof,
    pub closing_comm_w: G1,
    /// One batched universal proof for the masked primary accumulator and
    /// the closing instance.
    pub decider: BatchProof,
}

fn grumpkin_words(out: &mut Vec<Word>, p: &Grumpkin) {
    let [x, y] = llull_folder::transcript::point_to_coords(p);
    out.push(word(&x));
    out.push(word(&y));
}

/// The claimed final IVC state: `(i, z_0, z_i, U, u, U_cf)`.
#[derive(Clone, Copy)]
struct Statement<'a> {
    i: u64,
    z0: &'a [Fr],
    zi: &'a [Fr],
    acc: &'a RelaxedR1CSInstance<G1>,
    last: &'a R1CSInstance<G1>,
    cf_acc: &'a CfRelaxedInstance<Grumpkin>,
}

impl RecursiveProof {
    fn statement(&self) -> Statement<'_> {
        Statement {
            i: self.i,
            z0: &self.z0,
            zi: &self.zi,
            acc: &self.acc,
            last: &self.last,
            cf_acc: &self.cf_acc,
        }
    }
}

/// The transcript prefix shared by prover and verifier, up to the first fold.
fn start(params: &RecursiveParams, st: Statement) -> KeccakTranscript {
    let mut tr = KeccakTranscript::new(DOMAIN);
    tr.absorb_words(&[params.primary.vk, params.closing.vk, params.cf_code_hash]);
    let mut claim = alloc::vec![word(&Fr::from(st.i))];
    claim.extend(st.z0.iter().chain(st.zi).map(word));
    tr.absorb_words(&claim);
    let mut words = Vec::new();
    relaxed_words(&mut words, st.acc);
    words.extend(point_words(&st.last.comm_w));
    words.extend(st.last.x.iter().map(word));
    tr.absorb_words(&words);
    tr
}

fn cf_words(cf: &CfRelaxedInstance<Grumpkin>) -> Vec<Word> {
    let mut words = Vec::new();
    for p in cf.comm_w.iter().chain(&cf.comm_e) {
        grumpkin_words(&mut words, p);
    }
    words.push(word(&cf.u));
    words.extend(cf.x.iter().map(word));
    words
}

fn padded(v: &[Fq], len: usize) -> Vec<Fq> {
    let mut out = v.to_vec();
    out.resize(len, Fq::zero());
    out
}

/// `(A + ρB + ρ²C)(r_x, r_y)`, evaluated by the verifier from the entries.
fn matrix_eval(shape: &R1CSShape<Fq>, rho: Fq, rx: &[Fq], ry: &[Fq]) -> Fq {
    let (ex, ey) = (eq_table(rx), eq_table(ry));
    let powers = [Fq::one(), rho, rho * rho];
    entries(shape)
        .iter()
        .map(|&(k, row, col, v)| powers[k] * v * ex[row] * ey[col])
        .sum()
}

/// `Σ_i IO_i·eq(r, i)` with `IO = (u, x, 0, …)`.
fn io_eval(u: Fq, x: &[Fq], r: &[Fq]) -> Fq {
    let eq = eq_table(r);
    core::iter::once(&u)
        .chain(x)
        .zip(&eq)
        .map(|(v, e)| *v * e)
        .sum()
}

/// The prover's side of the CycleFold argument: outer messages, claims,
/// inner messages, `r_x`, `r_y` and `W̃(r_y[1..])`.
type CfTranscript = (Vec<Fq>, [Fq; 4], Vec<Fq>, Vec<Fq>, Vec<Fq>, Fq);

/// Prover side of the Spartan argument over `Fq` (steps 1–2 of the module
/// documentation, without commitments: the verifier knows the matrices).
fn cf_prove(
    shape: &R1CSShape<Fq>,
    acc: &CfRelaxedInstance<Grumpkin>,
    wit: &CfRelaxedWitness<Fq>,
    tr: &mut KeccakTranscript,
) -> CfTranscript {
    let dims = CfDims::of(shape);
    let (m, n) = (1 << dims.log_m, 1 << dims.log_n);
    let tau = tr.challenges_q(dims.log_m);
    let z = shape
        .z(&wit.w, &acc.x, acc.u)
        .expect("witness matches the shape");
    let (az, bz, cz) = shape.mul_z(&z);
    let mut tables = [
        eq_table(&tau),
        padded(&az, m),
        padded(&bz, m),
        padded(&cz, m),
        padded(&wit.e, m),
    ];
    let u = acc.u;
    let (outer, rx) = sumcheck::prove(
        &mut tables,
        3,
        |v| v[0] * (v[1] * v[2] - u * v[3] - v[4]),
        tr,
    );
    let claims = [tables[1][0], tables[2][0], tables[3][0], tables[4][0]];
    tr.absorb_fq(&claims);

    let rho = tr.challenge_q();
    let ex = eq_table(&rx);
    let powers = [Fq::one(), rho, rho * rho];
    let mut mtab = alloc::vec![Fq::zero(); 2 * n];
    for (k, row, col, v) in entries(shape) {
        mtab[col] += powers[k] * v * ex[row];
    }
    let mut ztab = padded(&wit.w, n);
    ztab.push(acc.u);
    ztab.extend_from_slice(&acc.x);
    ztab.resize(2 * n, Fq::zero());
    let mut tables = [mtab, ztab];
    let (inner, ry) = sumcheck::prove(&mut tables, 2, |v| v[0] * v[1], tr);
    let w_eq = eq_table(&ry[1..]);
    let v_w: Fq = wit.w.iter().zip(&w_eq).map(|(a, b)| *a * b).sum();
    tr.absorb_fq(&[v_w]);
    (outer, claims, inner, rx, ry, v_w)
}

/// The closing circuit's public input, as the verifier assembles it.
fn closing_inputs(st: Statement, weights: &[Fq], combined: &[Fq]) -> Vec<Fr> {
    let mut x = alloc::vec![st.last.x[0], Fr::from(st.i)];
    x.extend_from_slice(st.z0);
    x.extend_from_slice(st.zi);
    absorb_primary(&mut x, st.acc);
    absorb_cf_acc(&mut x, st.cf_acc);
    for s in weights {
        x.extend(llull_folder::transcript::scalar_to_limbs::<Fq, Fr>(&odd_t(
            *s,
        )));
    }
    for c in combined {
        x.extend(llull_folder::transcript::scalar_to_limbs::<Fq, Fr>(c));
    }
    x
}

/// Row weights `s = (γ·L_W, L_E)` and the combined row `c = γ·w' + e'`.
fn weights_and_row(proof: &CfProof, rx: &[Fq], ry: &[Fq], gamma: Fq) -> (Vec<Fq>, Vec<Fq>) {
    let log_cols = CF_COLUMNS.trailing_zeros() as usize;
    let r_w = &ry[1..];
    let l_w = eq_table(&r_w[..r_w.len() - log_cols]);
    let l_e = eq_table(&rx[..rx.len() - log_cols]);
    let mut weights: Vec<Fq> = l_w.iter().map(|l| gamma * l).collect();
    weights.extend(l_e);
    let combined = proof
        .w_row
        .iter()
        .zip(&proof.e_row)
        .map(|(w, e)| gamma * w + e)
        .collect();
    (weights, combined)
}

fn closing_instance(closing_comm_w: G1, x: Vec<Fr>) -> RelaxedR1CSInstance<G1> {
    RelaxedR1CSInstance {
        comm_e: G1::zero(),
        u: Fr::one(),
        comm_w: closing_comm_w,
        x,
    }
}

/// Produces the recursive decider proof for a final IVC state. Refuses to
/// prove an invalid state and never returns a proof [`verify`] rejects.
pub fn prove(
    params: &RecursiveParams,
    ivc: &CycleFoldAccumulator<Bn254Config, GrumpkinConfig>,
    rng: &mut impl RngCore,
) -> Result<RecursiveProof, DeciderError> {
    ivc.verify(&params.ivc)
        .map_err(|_| DeciderError::Unsatisfied)?;
    let (rows_w, rows_e) = params.ivc.cf_rows();
    // The opening below relies on full rows: 2^k rows of CF_COLUMNS columns.
    assert!(rows_w.is_power_of_two() && rows_e.is_power_of_two());
    let shape = &params.ivc.shape;
    let ck = &params.ivc.ck;
    let st = Statement {
        i: ivc.i,
        z0: &ivc.z0,
        zi: &ivc.zi,
        acc: &ivc.acc.0,
        last: &ivc.last.0,
        cf_acc: &ivc.cf.0,
    };
    let mut tr = start(params, st);

    // 1. Fold the last instance, then mask.
    let (acc1, wit1, comm_t) = nifs_prove_with(
        ck,
        shape,
        &ivc.acc.0,
        &ivc.acc.1,
        &ivc.last.0,
        &ivc.last.1,
        rng,
        |t| {
            tr.absorb_points(&[*t]);
            tr.challenge()
        },
    )?;
    let (mask, mask_w) = llull_folder::sample_relaxed(ck, shape, rng);
    let mut words = Vec::new();
    relaxed_words(&mut words, &mask);
    tr.absorb_words(&words);
    let (acc2, wit2, mask_t) =
        nifs_prove_relaxed_with(ck, shape, &acc1, &wit1, &mask, &mask_w, rng, |t| {
            tr.absorb_points(&[*t]);
            tr.challenge()
        })?;

    // 2. The CycleFold accumulator over Fq.
    tr.absorb_words(&cf_words(&ivc.cf.0));
    let (outer, claims, inner, rx, ry, v_w) =
        cf_prove(&params.ivc.cf_shape, &ivc.cf.0, &ivc.cf.1, &mut tr);
    let (_, e_row, e_eval) = hyrax_open(&ivc.cf.1.e, CF_COLUMNS, &rx);
    let (_, w_row, w_eval) = hyrax_open(&ivc.cf.1.w, CF_COLUMNS, &ry[1..]);
    debug_assert_eq!((e_eval, w_eval), (claims[3], v_w));
    tr.absorb_fq(&e_row);
    tr.absorb_fq(&w_row);
    let gamma = tr.challenge_q();
    let cf = CfProof {
        outer,
        claims,
        inner,
        v_w,
        e_row,
        w_row,
    };
    let (row_weights, combined) = weights_and_row(&cf, &rx, &ry, gamma);

    // 3. The closing circuit and its instance.
    let closing = ClosingCircuit::<Bn254Config, GrumpkinConfig> {
        poseidon: &params.ivc.poseidon,
        digest: params.ivc.digest,
        gens: &params.ivc.cf_key.ck.gens,
        i: ivc.i,
        z0: ivc.z0.clone(),
        zi: ivc.zi.clone(),
        acc: ivc.acc.0.clone(),
        cf_acc: ivc.cf.0.clone(),
        row_weights: row_weights.clone(),
        combined: combined.clone(),
    };
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });
    closing
        .synthesize(cs.clone())
        .map_err(|_| DeciderError::Unsatisfied)?;
    let (w, x) = assignment_from_cs(&cs).map_err(|_| DeciderError::Unsatisfied)?;
    drop(cs);
    if x != closing_inputs(st, &row_weights, &combined) {
        return Err(DeciderError::Unsatisfied);
    }
    let r_w = Fr::rand(rng);
    let closing_comm_w = params.closing.ck.commit(&w, r_w);
    let closing_wit = RelaxedR1CSWitness {
        e: alloc::vec![Fr::zero(); params.closing.shape.num_constraints],
        r_e: Fr::zero(),
        w,
        r_w,
    };
    let inst = closing_instance(closing_comm_w, x);

    // 4. The masked primary accumulator and the closing instance, together.
    let decider = batch::prove(
        &[
            Item {
                params: &params.primary,
                key: &params.primary_key,
                acc: &acc2,
            },
            Item {
                params: &params.closing,
                key: &params.closing_key,
                acc: &inst,
            },
        ],
        &[&wit2, &closing_wit],
    );

    let proof = RecursiveProof {
        i: ivc.i,
        z0: ivc.z0.clone(),
        zi: ivc.zi.clone(),
        acc: ivc.acc.0.clone(),
        last: ivc.last.0.clone(),
        comm_t,
        mask,
        mask_t,
        cf_acc: ivc.cf.0.clone(),
        cf,
        closing_comm_w,
        decider,
    };
    if !verify(params, &proof) {
        return Err(DeciderError::Unsatisfied);
    }
    Ok(proof)
}

/// The verifier, step for step what `finalizeRecursive` does.
pub fn verify(params: &RecursiveParams, p: &RecursiveProof) -> bool {
    let ivc = &params.ivc;
    let (rows_w, rows_e) = ivc.cf_rows();
    let arity = ivc.arity;
    let dims = CfDims::of(&ivc.cf_shape);
    let well_formed = p.z0.len() == arity
        && p.zi.len() == arity
        && p.acc.x.len() == 1
        && p.last.x.len() == 1
        && p.mask.x.len() == 1
        && p.cf_acc.comm_w.len() == rows_w
        && p.cf_acc.comm_e.len() == rows_e
        && p.cf_acc.x.len() == CF_IO_LEN
        && p.cf.outer.len() == 3 * dims.log_m
        && p.cf.inner.len() == 2 * (dims.log_n + 1)
        && p.cf.e_row.len() == CF_COLUMNS
        && p.cf.w_row.len() == CF_COLUMNS
        && params.primary.tau_g2 == params.closing.tau_g2;
    if !well_formed || p.i == 0 {
        return false;
    }
    let Some(tau_g2) = params.primary.tau_g2 else {
        return false;
    };
    let mut tr = start(params, p.statement());

    // 1. The two folds.
    tr.absorb_points(&[p.comm_t]);
    let r1 = tr.challenge();
    let acc1 = fold_instance(&p.acc, &p.last, &p.comm_t, r1);
    let mut words = Vec::new();
    relaxed_words(&mut words, &p.mask);
    tr.absorb_words(&words);
    tr.absorb_points(&[p.mask_t]);
    let r2 = tr.challenge();
    let acc2 = fold_relaxed_instance(&acc1, &p.mask, &p.mask_t, r2);

    // 2. The CycleFold accumulator over Fq.
    tr.absorb_words(&cf_words(&p.cf_acc));
    let tau = tr.challenges_q(dims.log_m);
    let Some((claim, rx)) = sumcheck::verify(Fq::zero(), dims.log_m, 3, &p.cf.outer, &mut tr)
    else {
        return false;
    };
    let [va, vb, vc, ve] = p.cf.claims;
    if claim != sumcheck::eq_points(&tau, &rx) * (va * vb - p.cf_acc.u * vc - ve) {
        return false;
    }
    tr.absorb_fq(&p.cf.claims);
    let rho = tr.challenge_q();
    let Some((claim, ry)) = sumcheck::verify(
        va + rho * vb + rho * rho * vc,
        dims.log_n + 1,
        2,
        &p.cf.inner,
        &mut tr,
    ) else {
        return false;
    };
    let z_eval =
        (Fq::one() - ry[0]) * p.cf.v_w + ry[0] * io_eval(p.cf_acc.u, &p.cf_acc.x, &ry[1..]);
    if claim != matrix_eval(&ivc.cf_shape, rho, &rx, &ry) * z_eval {
        return false;
    }
    tr.absorb_fq(&[p.cf.v_w]);
    // The Hyrax rows open Ẽ(r_x) and W̃(r_y[1..]) …
    let log_cols = CF_COLUMNS.trailing_zeros() as usize;
    let inner = |row: &[Fq], r: &[Fq]| -> Fq {
        row.iter()
            .zip(eq_table(&r[r.len() - log_cols..]))
            .map(|(a, b)| *a * b)
            .sum()
    };
    if inner(&p.cf.e_row, &rx) != ve || inner(&p.cf.w_row, &ry[1..]) != p.cf.v_w {
        return false;
    }
    tr.absorb_fq(&p.cf.e_row);
    tr.absorb_fq(&p.cf.w_row);
    let gamma = tr.challenge_q();
    // … if Σ s_i·C_i = Σ c_j·G_j, which the closing circuit proves.
    let (weights, combined) = weights_and_row(&p.cf, &rx, &ry, gamma);
    let inst = closing_instance(
        p.closing_comm_w,
        closing_inputs(p.statement(), &weights, &combined),
    );

    // 3–4. One batched universal proof for both, one pairing check.
    let items = [
        Item {
            params: &params.primary,
            key: &params.primary_key,
            acc: &acc2,
        },
        Item {
            params: &params.closing,
            key: &params.closing_key,
            acc: &inst,
        },
    ];
    let Some((left, right)) = batch::verify_deferred(&items, &p.decider) else {
        return false;
    };
    universal::hyperkzg::pairing_check(left, right, tau_g2)
}

/// `state` of `finalizeRecursive`: `[i, k, z₀, zᵢ, U(6), u(3), comm_T(2),
/// mask(6), mask_T(2), U_cf rows of W, rows of E (2 words each), U_cf.u,
/// U_cf.x]`.
pub fn state_words(p: &RecursiveProof) -> Vec<Word> {
    let mut out = alloc::vec![word(&Fr::from(p.i)), word(&Fr::from(p.z0.len() as u64))];
    out.extend(p.z0.iter().chain(&p.zi).map(word));
    relaxed_words(&mut out, &p.acc);
    out.extend(point_words(&p.last.comm_w));
    out.extend(p.last.x.iter().map(word));
    out.extend(point_words(&p.comm_t));
    relaxed_words(&mut out, &p.mask);
    out.extend(point_words(&p.mask_t));
    out.extend(cf_words(&p.cf_acc));
    out
}

/// `cfProof` of `finalizeRecursive`: `[outer, claims, inner, W(r_y'), e', w',
/// closing comm_W]`.
pub fn cf_proof_words(p: &RecursiveProof) -> Vec<Word> {
    let cf = &p.cf;
    let mut out: Vec<Word> = cf.outer.iter().map(word).collect();
    out.extend(cf.claims.iter().map(word));
    out.extend(cf.inner.iter().map(word));
    out.push(word(&cf.v_w));
    out.extend(cf.e_row.iter().chain(&cf.w_row).map(word));
    out.extend(point_words(&p.closing_comm_w));
    out
}

/// The five word arrays of `finalizeRecursive`, in argument order.
pub fn arguments(params: &RecursiveParams, p: &RecursiveProof) -> [Vec<Word>; 5] {
    let key = |ev: &EvmParams, k: &CircuitKey| {
        k.contract_words(&ev.ck.h, &ev.tau_g2.expect("KZG parameters"))
    };
    [
        key(&params.primary, &params.primary_key),
        key(&params.closing, &params.closing_key),
        state_words(p),
        cf_proof_words(p),
        p.decider.words(),
    ]
}

/// ABI-encoded `finalizeRecursive(uint256[] ×5)` and, for every argument,
/// the byte offset of its first word in the calldata.
pub fn calldata(params: &RecursiveParams, p: &RecursiveProof) -> (Vec<u8>, [usize; 5]) {
    let args = arguments(params, p);
    let sig = "finalizeRecursive(uint256[],uint256[],uint256[],uint256[],uint256[])";
    let hash = Keccak256::digest(sig.as_bytes());
    let mut out = hash[..4].to_vec();
    let uint = |v: usize| -> Word {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(v as u64).to_be_bytes());
        w
    };
    let mut offset = 32 * args.len();
    for a in &args {
        out.extend(uint(offset));
        offset += 32 * (1 + a.len());
    }
    let mut starts = [0usize; 5];
    for (i, a) in args.iter().enumerate() {
        out.extend(uint(a.len()));
        starts[i] = out.len();
        for w in a {
            out.extend(w);
        }
    }
    (out, starts)
}
