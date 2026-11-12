//! The universal decider: a holographic Spartan-style argument for the
//! relaxed R1CS relation of a KZG-committed accumulator.
//!
//! **Preprocessing (public, deterministic, no secrets).** The matrices
//! `A, B, C` are flattened into one list of `K` non-zero entries
//! `(row_k, col_k, val_k)` and committed as polynomials `row`, `col`,
//! `val_A`, `val_B`, `val_C`, together with the multiplicities `count_row`,
//! `count_col` of every row / column index. Anyone can recompute these
//! commitments from the circuit and the reference string.
//!
//! **Proof.**
//! 1. Outer sum-check: `Σ_x eq(τ,x)·(Az·Bz − u·Cz − E)(x) = 0` → point `r_x`.
//! 2. Inner sum-check: `Σ_y (A+ρB+ρ²C)(r_x,y)·Z(y) = v_A+ρv_B+ρ²v_C` → `r_y`,
//!    leaving the claim `M(r_x, r_y) = v_M` about the *matrices*.
//! 3. Matrix evaluation without reading the matrices: the prover commits to
//!    `e_row_k = eq(r_x, row_k)` and `e_col_k = eq(r_y, col_k)` and proves
//!    `Σ_k val_k·e_row_k·e_col_k = v_M`. That every `e_row_k` really is the
//!    table entry `eq(r_x, ·)[row_k]` is a lookup, proven with logarithmic
//!    derivatives (LogUp):
//!    `Σ_k 1/(γ + row_k + β·e_row_k) = Σ_j count_row_j/(γ + j + β·eq(r_x, j))`,
//!    and likewise for columns.
//! 4. All remaining claims are multilinear evaluations of committed
//!    polynomials, opened with HyperKZG and checked by a single pairing.
//!
//! The verifier's work is logarithmic in the circuit size plus a constant
//! number of pairings, which is what makes an EVM verifier possible.

use super::{
    hyperkzg::{self, mle_eval, HyperKzgProof},
    transcript::KeccakTranscript,
};
use crate::{point_words, word, EvmParams, Word};
use alloc::vec::Vec;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{batch_inversion, One, Zero};
use core_r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness, SparseMatrix};
use decider_zk::sumcheck::{self, eq_points, eq_table};
use sha3::{Digest, Keccak256};

fn log2_ceil(v: usize) -> usize {
    v.next_power_of_two().trailing_zeros() as usize
}

/// Padded dimensions of the argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dims {
    /// `2^log_m` constraint rows.
    pub log_m: usize,
    /// `Z = (W ‖ (u, x))` with `2^log_n` entries in each half.
    pub log_n: usize,
    /// `2^log_k` matrix entries (all three matrices, padded).
    pub log_k: usize,
}

impl Dims {
    pub fn of(shape: &R1CSShape<Fr>) -> Self {
        let entries = shape.a.nnz() + shape.b.nnz() + shape.c.nnz();
        Self {
            log_m: log2_ceil(shape.num_constraints.max(4)),
            log_n: log2_ceil(shape.num_vars.max(shape.num_io + 1).max(4)),
            log_k: log2_ceil(entries.max(4)),
        }
    }
    fn m(&self) -> usize {
        1 << self.log_m
    }
    fn n(&self) -> usize {
        1 << self.log_n
    }
    fn z(&self) -> usize {
        2 << self.log_n
    }
    fn k(&self) -> usize {
        1 << self.log_k
    }
    /// Length of the reference string the argument needs.
    pub fn srs_len(&self) -> usize {
        self.m().max(self.z()).max(self.k())
    }
}

/// Column of the engine's `Z = (W, x, u)` inside the padded `(W ‖ (u, x))`.
fn remap(shape: &R1CSShape<Fr>, n: usize, col: usize) -> usize {
    if col < shape.num_vars {
        col
    } else if col == shape.num_vars + shape.num_io {
        n
    } else {
        n + 1 + (col - shape.num_vars)
    }
}

/// The preprocessed circuit: its matrices as committed polynomials.
#[derive(Clone, Debug)]
pub struct CircuitKey {
    pub dims: Dims,
    row_idx: Vec<usize>,
    col_idx: Vec<usize>,
    row: Vec<Fr>,
    col: Vec<Fr>,
    /// `val_A`, `val_B`, `val_C`: each zero outside its matrix' entries.
    val: [Vec<Fr>; 3],
    count_row: Vec<Fr>,
    count_col: Vec<Fr>,
    /// Commitments to `row, col, val_A, val_B, val_C, count_row, count_col`.
    pub comms: [G1; 7],
}

impl CircuitKey {
    /// Commits to the circuit's matrices. Deterministic and public: it uses
    /// only the circuit and the reference string, no secret randomness.
    pub fn preprocess(params: &EvmParams) -> Self {
        let shape = &params.shape;
        let dims = Dims::of(shape);
        assert!(
            params.ck.len() >= dims.srs_len(),
            "reference string too short: the universal decider needs {} powers",
            dims.srs_len()
        );
        let (n, k) = (dims.n(), dims.k());
        let mut row_idx = alloc::vec![0usize; k];
        let mut col_idx = alloc::vec![0usize; k];
        let mut val = [
            alloc::vec![Fr::zero(); k],
            alloc::vec![Fr::zero(); k],
            alloc::vec![Fr::zero(); k],
        ];
        let matrices: [&SparseMatrix<Fr>; 3] = [&shape.a, &shape.b, &shape.c];
        let mut next = 0;
        for (which, matrix) in matrices.iter().enumerate() {
            for i in 0..matrix.num_rows {
                for e in matrix.row_ptr[i]..matrix.row_ptr[i + 1] {
                    row_idx[next] = i;
                    col_idx[next] = remap(shape, n, matrix.col_idx[e]);
                    val[which][next] = matrix.values[e];
                    next += 1;
                }
            }
        }
        // Padding entries point at (0, 0) with value 0; they are counted too.
        let mut count_row = alloc::vec![Fr::zero(); dims.m()];
        let mut count_col = alloc::vec![Fr::zero(); dims.z()];
        for (r, c) in row_idx.iter().zip(&col_idx) {
            count_row[*r] += Fr::one();
            count_col[*c] += Fr::one();
        }
        let as_field = |idx: &[usize]| idx.iter().map(|i| Fr::from(*i as u64)).collect::<Vec<_>>();
        let (row, col) = (as_field(&row_idx), as_field(&col_idx));
        let commit = |v: &[Fr]| params.ck.commit(v, Fr::zero());
        let comms = [
            commit(&row),
            commit(&col),
            commit(&val[0]),
            commit(&val[1]),
            commit(&val[2]),
            commit(&count_row),
            commit(&count_col),
        ];
        Self {
            dims,
            row_idx,
            col_idx,
            row,
            col,
            val,
            count_row,
            count_col,
            comms,
        }
    }

    /// The circuit-specific words of the decider key: the three dimensions
    /// and the seven commitments. Public and recomputable by anyone.
    pub fn words(&self) -> Vec<Word> {
        let d = self.dims;
        let mut words: Vec<Word> = [d.log_m, d.log_n, d.log_k]
            .iter()
            .map(|v| word(&Fr::from(*v as u64)))
            .collect();
        words.extend(self.comms.iter().flat_map(point_words));
        words
    }

    /// `keccak256` of [`Self::words`].
    pub fn digest(&self) -> Word {
        let mut h = Keccak256::new();
        for w in self.words() {
            h.update(w);
        }
        h.finalize().into()
    }
}

/// The universal decider proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniversalProof {
    pub r_w: Fr,
    pub r_e: Fr,
    pub outer: Vec<Fr>,
    /// `(Az)(r_x), (Bz)(r_x), (Cz)(r_x), E(r_x)`.
    pub claims: [Fr; 4],
    pub inner: Vec<Fr>,
    /// `(A+ρB+ρ²C)(r_x, r_y)` and `W(r_y[1..])`.
    pub v_m: Fr,
    pub v_w: Fr,
    /// Commitments to `e_row, e_col, h1_row, h1_col, h2_row, h2_col`.
    pub comms: [G1; 6],
    /// The two LogUp sums.
    pub sums: [Fr; 2],
    pub sc_k: Vec<Fr>,
    /// `val_A, val_B, val_C, row, col, e_row, e_col, h1_row, h1_col` at `r_k`.
    pub evals_k: [Fr; 9],
    pub sc_m: Vec<Fr>,
    /// `h2_row, count_row` at `r_j`.
    pub evals_m: [Fr; 2],
    pub sc_z: Vec<Fr>,
    /// `h2_col, count_col` at `r_z`.
    pub evals_z: [Fr; 2],
    /// Openings of: `E`; `W`; the nine `K`-polynomials; the two row-table
    /// polynomials; the two column-table polynomials.
    pub openings: [HyperKzgProof; 5],
}

impl UniversalProof {
    /// The proof as the flat word array the contract parses, in protocol
    /// order; every length is determined by the circuit's dimensions.
    pub fn words(&self) -> Vec<Word> {
        let scalars = |out: &mut Vec<Word>, v: &[Fr]| out.extend(v.iter().map(word));
        let points = |out: &mut Vec<Word>, v: &[G1]| out.extend(v.iter().flat_map(point_words));
        let mut w = Vec::new();
        scalars(&mut w, &[self.r_w, self.r_e]);
        scalars(&mut w, &self.outer);
        scalars(&mut w, &self.claims);
        scalars(&mut w, &self.inner);
        scalars(&mut w, &[self.v_m, self.v_w]);
        points(&mut w, &self.comms);
        scalars(&mut w, &self.sums);
        scalars(&mut w, &self.sc_k);
        scalars(&mut w, &self.evals_k);
        scalars(&mut w, &self.sc_m);
        scalars(&mut w, &self.evals_m);
        scalars(&mut w, &self.sc_z);
        scalars(&mut w, &self.evals_z);
        for o in &self.openings {
            points(&mut w, &o.comms);
            scalars(&mut w, &o.y_pos);
            scalars(&mut w, &o.y_neg);
            scalars(&mut w, &o.y_sq);
            points(&mut w, &o.pi);
        }
        w
    }

    /// Size of the proof as EVM calldata (32-byte words).
    pub fn size_bytes(&self) -> usize {
        32 * self.words().len()
    }
}

fn start(
    params: &EvmParams,
    key_digest: &Word,
    acc: &RelaxedR1CSInstance<G1>,
    r_w: &Fr,
    r_e: &Fr,
) -> KeccakTranscript {
    let mut tr = KeccakTranscript::new(b"zeno-llull/universal-decider/v1");
    let mut words = alloc::vec![params.vk, *key_digest];
    words.extend(point_words(&acc.comm_e));
    words.push(word(&acc.u));
    words.extend(point_words(&acc.comm_w));
    words.extend(acc.x.iter().map(word));
    words.push(word(r_w));
    words.push(word(r_e));
    tr.absorb_words(&words);
    tr
}

fn padded(v: &[Fr], len: usize) -> Vec<Fr> {
    let mut out = v.to_vec();
    out.resize(len, Fr::zero());
    out
}

/// The multilinear extension of the table `j ↦ j`, at `point`.
fn index_mle(point: &[Fr]) -> Fr {
    point.iter().fold(Fr::zero(), |acc, p| acc + acc + p)
}

/// Summands of the three lookup/product sum-checks; shared by the prover
/// (on tables) and the verifier (on the evaluations at the final point).
struct Challenges {
    beta: Fr,
    gamma: Fr,
}

/// `[val_ρ, e_row, e_col, h1_row, h1_col, eq_τ, row, col]`.
fn summand_k(v: &[Fr], ch: &Challenges, delta: Fr) -> Fr {
    let d2 = delta * delta;
    v[0] * v[1] * v[2]
        + delta * v[3]
        + d2 * v[4]
        + d2 * delta * v[5] * (v[3] * (ch.gamma + v[6] + ch.beta * v[1]) - Fr::one())
        + d2 * d2 * v[5] * (v[4] * (ch.gamma + v[7] + ch.beta * v[2]) - Fr::one())
}

/// `[h2, eq_τ, index, table, count]`.
fn summand_table(v: &[Fr], ch: &Challenges, delta: Fr) -> Fr {
    v[0] + delta * v[1] * (v[0] * (ch.gamma + v[2] + ch.beta * v[3]) - v[4])
}

fn inverses(mut denominators: Vec<Fr>) -> Vec<Fr> {
    batch_inversion(&mut denominators);
    denominators
}

/// Proves that `(acc, witness)` satisfies the relaxed R1CS relation.
/// `params` must come from [`EvmParams::setup_universal`].
pub fn prove(
    params: &EvmParams,
    key: &CircuitKey,
    acc: &RelaxedR1CSInstance<G1>,
    witness: &RelaxedR1CSWitness<G1>,
) -> UniversalProof {
    let shape = &params.shape;
    let dims = key.dims;
    let (m, n, z_len) = (dims.m(), dims.n(), dims.z());
    let commit = |v: &[Fr]| params.ck.commit(v, Fr::zero());
    let mut tr = start(params, &key.digest(), acc, &witness.r_w, &witness.r_e);

    // ---- 1. Outer sum-check ----------------------------------------------
    let tau = tr.challenges(dims.log_m);
    let z = shape
        .z(&witness.w, &acc.x, acc.u)
        .expect("witness matches the shape");
    let (az, bz, cz) = shape.mul_z(&z);
    let e_padded = padded(&witness.e, m);
    let mut tables = [
        eq_table(&tau),
        padded(&az, m),
        padded(&bz, m),
        padded(&cz, m),
        e_padded.clone(),
    ];
    let u = acc.u;
    let (outer, rx) = sumcheck::prove(
        &mut tables,
        3,
        |v| v[0] * (v[1] * v[2] - u * v[3] - v[4]),
        &mut tr,
    );
    let claims = [tables[1][0], tables[2][0], tables[3][0], tables[4][0]];
    tr.absorb_scalars(&claims);

    // ---- 2. Inner sum-check ----------------------------------------------
    let rho = tr.challenge();
    let rho_pow = [Fr::one(), rho, rho * rho];
    let eq_rx = eq_table(&rx);
    let val_rho: Vec<Fr> = (0..dims.k())
        .map(|k| key.val[0][k] + rho * key.val[1][k] + rho_pow[2] * key.val[2][k])
        .collect();
    let mut combined = alloc::vec![Fr::zero(); z_len];
    for k in 0..dims.k() {
        combined[key.col_idx[k]] += eq_rx[key.row_idx[k]] * val_rho[k];
    }
    let w_padded = padded(&witness.w, n);
    let mut z_padded = w_padded.clone();
    z_padded.push(acc.u);
    z_padded.extend_from_slice(&acc.x);
    z_padded.resize(z_len, Fr::zero());
    let mut tables = [combined, z_padded];
    let (inner, ry) = sumcheck::prove(&mut tables, 2, |v| v[0] * v[1], &mut tr);
    let v_m = tables[0][0];
    let v_w = mle_eval(&w_padded, &ry[1..]);
    tr.absorb_scalars(&[v_m, v_w]);

    // ---- 3. Lookups of eq(r_x, ·) and eq(r_y, ·) at the matrix indices ----
    let eq_ry = eq_table(&ry);
    let e_row: Vec<Fr> = key.row_idx.iter().map(|i| eq_rx[*i]).collect();
    let e_col: Vec<Fr> = key.col_idx.iter().map(|i| eq_ry[*i]).collect();
    let (c_er, c_ec) = (commit(&e_row), commit(&e_col));
    tr.absorb_points(&[c_er, c_ec]);
    let ch = Challenges {
        beta: tr.challenge(),
        gamma: tr.challenge(),
    };
    let lookup = |idx: &[Fr], e: &[Fr]| {
        inverses(
            idx.iter()
                .zip(e)
                .map(|(i, e)| ch.gamma + i + ch.beta * e)
                .collect(),
        )
    };
    let table = |eq: &[Fr], count: &[Fr]| -> Vec<Fr> {
        let inv = inverses(
            eq.iter()
                .enumerate()
                .map(|(j, t)| ch.gamma + Fr::from(j as u64) + ch.beta * t)
                .collect(),
        );
        inv.iter().zip(count).map(|(i, c)| *i * c).collect()
    };
    let h1r = lookup(&key.row, &e_row);
    let h1c = lookup(&key.col, &e_col);
    let h2r = table(&eq_rx, &key.count_row);
    let h2c = table(&eq_ry, &key.count_col);
    let comms = [
        c_er,
        c_ec,
        commit(&h1r),
        commit(&h1c),
        commit(&h2r),
        commit(&h2c),
    ];
    tr.absorb_points(&comms[2..]);
    let sums = [h1r.iter().sum::<Fr>(), h1c.iter().sum::<Fr>()];
    tr.absorb_scalars(&sums);

    // ---- 4. Sum-check over the matrix entries ------------------------------
    let delta = tr.challenge();
    let tau_k = tr.challenges(dims.log_k);
    let mut tables = [
        val_rho,
        e_row.clone(),
        e_col.clone(),
        h1r.clone(),
        h1c.clone(),
        eq_table(&tau_k),
        key.row.clone(),
        key.col.clone(),
    ];
    let (sc_k, rk) = sumcheck::prove(&mut tables, 3, |v| summand_k(v, &ch, delta), &mut tr);
    let polys_k: [&[Fr]; 9] = [
        &key.val[0],
        &key.val[1],
        &key.val[2],
        &key.row,
        &key.col,
        &e_row,
        &e_col,
        &h1r,
        &h1c,
    ];
    let evals_k: [Fr; 9] = core::array::from_fn(|i| mle_eval(polys_k[i], &rk));
    tr.absorb_scalars(&evals_k);

    // ---- 5. Sum-checks over the two lookup tables ---------------------------
    let ids = |len: usize| (0..len as u64).map(Fr::from).collect::<Vec<_>>();
    let delta_m = tr.challenge();
    let tau_m = tr.challenges(dims.log_m);
    let mut tables = [
        h2r.clone(),
        eq_table(&tau_m),
        ids(m),
        eq_rx,
        key.count_row.clone(),
    ];
    let (sc_m, rj) = sumcheck::prove(&mut tables, 3, |v| summand_table(v, &ch, delta_m), &mut tr);
    let evals_m = [tables[0][0], tables[4][0]];
    tr.absorb_scalars(&evals_m);

    let delta_z = tr.challenge();
    let tau_z = tr.challenges(dims.log_n + 1);
    let mut tables = [
        h2c.clone(),
        eq_table(&tau_z),
        ids(z_len),
        eq_ry,
        key.count_col.clone(),
    ];
    let (sc_z, rz) = sumcheck::prove(&mut tables, 3, |v| summand_table(v, &ch, delta_z), &mut tr);
    let evals_z = [tables[0][0], tables[4][0]];
    tr.absorb_scalars(&evals_z);

    // ---- 6. Openings ---------------------------------------------------------
    let ck = &params.ck;
    let openings = [
        hyperkzg::prove(&mut tr, ck, &[&e_padded], &rx, &claims[3..]),
        hyperkzg::prove(&mut tr, ck, &[&w_padded], &ry[1..], &[v_w]),
        hyperkzg::prove(&mut tr, ck, &polys_k, &rk, &evals_k),
        hyperkzg::prove(&mut tr, ck, &[&h2r, &key.count_row], &rj, &evals_m),
        hyperkzg::prove(&mut tr, ck, &[&h2c, &key.count_col], &rz, &evals_z),
    ];

    UniversalProof {
        r_w: witness.r_w,
        r_e: witness.r_e,
        outer,
        claims,
        inner,
        v_m,
        v_w,
        comms,
        sums,
        sc_k,
        evals_k,
        sc_m,
        evals_m,
        sc_z,
        evals_z,
        openings,
    }
}

/// Verifies a universal decider proof for the accumulator `acc`, given only
/// the circuit's commitments (`key.comms`, `key.dims`). Logarithmic work plus
/// one pairing check.
pub fn verify(
    params: &EvmParams,
    key: &CircuitKey,
    acc: &RelaxedR1CSInstance<G1>,
    proof: &UniversalProof,
) -> bool {
    let Some(tau_g2) = params.tau_g2 else {
        return false;
    };
    let dims = key.dims;
    if acc.x.len() != params.shape.num_io {
        return false;
    }
    let mut tr = start(params, &key.digest(), acc, &proof.r_w, &proof.r_e);

    // 1. Outer sum-check.
    let tau = tr.challenges(dims.log_m);
    let Some((claim, rx)) = sumcheck::verify(Fr::zero(), dims.log_m, 3, &proof.outer, &mut tr)
    else {
        return false;
    };
    let [va, vb, vc, ve] = proof.claims;
    if claim != eq_points(&tau, &rx) * (va * vb - acc.u * vc - ve) {
        return false;
    }
    tr.absorb_scalars(&proof.claims);

    // 2. Inner sum-check.
    let rho = tr.challenge();
    let Some((claim, ry)) = sumcheck::verify(
        va + rho * vb + rho * rho * vc,
        dims.log_n + 1,
        2,
        &proof.inner,
        &mut tr,
    ) else {
        return false;
    };
    // Z(r_y) = (1 − r_y0)·W(r_y') + r_y0·IO(r_y'), with IO = (u, x, 0, …).
    let tail = &ry[1..];
    let io_eval = core::iter::once(&acc.u)
        .chain(&acc.x)
        .enumerate()
        .fold(Fr::zero(), |sum, (i, v)| {
            sum + *v * sumcheck::eq_at(tail, i)
        });
    let z_eval = (Fr::one() - ry[0]) * proof.v_w + ry[0] * io_eval;
    if claim != proof.v_m * z_eval {
        return false;
    }
    tr.absorb_scalars(&[proof.v_m, proof.v_w]);

    // 3. Lookup commitments and sums.
    tr.absorb_points(&proof.comms[..2]);
    let ch = Challenges {
        beta: tr.challenge(),
        gamma: tr.challenge(),
    };
    tr.absorb_points(&proof.comms[2..]);
    tr.absorb_scalars(&proof.sums);

    // 4. Sum-check over the matrix entries.
    let delta = tr.challenge();
    let tau_k = tr.challenges(dims.log_k);
    let claim_k = proof.v_m + delta * proof.sums[0] + delta * delta * proof.sums[1];
    let Some((claim, rk)) = sumcheck::verify(claim_k, dims.log_k, 3, &proof.sc_k, &mut tr) else {
        return false;
    };
    let e = &proof.evals_k;
    let at_rk = [
        e[0] + rho * e[1] + rho * rho * e[2],
        e[5],
        e[6],
        e[7],
        e[8],
        eq_points(&tau_k, &rk),
        e[3],
        e[4],
    ];
    if claim != summand_k(&at_rk, &ch, delta) {
        return false;
    }
    tr.absorb_scalars(&proof.evals_k);

    // 5. Sum-checks over the two lookup tables; the tables eq(r_x, ·),
    //    eq(r_y, ·) and j ↦ j are evaluated by the verifier itself.
    let mut table_check = |log: usize, sum: Fr, msgs: &[Fr], evals: &[Fr; 2], point: &[Fr]| {
        let delta = tr.challenge();
        let tau = tr.challenges(log);
        let (claim, r) = sumcheck::verify(sum, log, 3, msgs, &mut tr)?;
        let at_r = [
            evals[0],
            eq_points(&tau, &r),
            index_mle(&r),
            eq_points(point, &r),
            evals[1],
        ];
        if claim != summand_table(&at_r, &ch, delta) {
            return None;
        }
        tr.absorb_scalars(evals);
        Some(r)
    };
    let Some(rj) = table_check(dims.log_m, proof.sums[0], &proof.sc_m, &proof.evals_m, &rx) else {
        return false;
    };
    let Some(rz) = table_check(
        dims.log_n + 1,
        proof.sums[1],
        &proof.sc_z,
        &proof.evals_z,
        &ry,
    ) else {
        return false;
    };

    // 6. Openings, all folded into one pairing check.
    let h = params.ck.h;
    let k = &key.comms;
    let p = &proof.comms;
    let claims: [(Vec<G1>, &[Fr], &[Fr]); 5] = [
        (
            alloc::vec![acc.comm_e - h * proof.r_e],
            &rx,
            &proof.claims[3..],
        ),
        (
            alloc::vec![acc.comm_w - h * proof.r_w],
            tail,
            core::slice::from_ref(&proof.v_w),
        ),
        (
            alloc::vec![k[2], k[3], k[4], k[0], k[1], p[0], p[1], p[2], p[3]],
            &rk,
            &proof.evals_k,
        ),
        (alloc::vec![p[4], k[5]], &rj, &proof.evals_m),
        (alloc::vec![p[5], k[6]], &rz, &proof.evals_z),
    ];
    let mut pairs = Vec::with_capacity(5);
    for ((comms, point, values), opening) in claims.iter().zip(&proof.openings) {
        let Some(pair) = hyperkzg::verify(&mut tr, comms, point, values, opening) else {
            return false;
        };
        pairs.push(pair);
    }
    let weight = tr.challenge();
    let mut w = Fr::one();
    let (mut left, mut right) = (G1::zero(), G1::zero());
    for (l, r) in pairs {
        left += l * w;
        right += r * w;
        w *= weight;
    }
    !weight.is_zero() && hyperkzg::pairing_check(left, right, tau_g2)
}
