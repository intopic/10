//! A transparent SNARK for the relaxed R1CS relation of one accumulator, in
//! the style of Spartan: two sum-checks reduce
//!
//! ```text
//! (A·Z) ∘ (B·Z) = u·(C·Z) + E,   comm_W = Com(W; r_W),   comm_E = Com(E; r_E)
//! ```
//!
//! to one evaluation of the multilinear extension of `E` and one of `W`,
//! each proven with an inner-product argument against the Pedersen
//! commitments the folding scheme already produced. No trusted setup, no FFT.
//!
//! The argument itself is not hiding (it reveals `r_W`, `r_E` and
//! evaluations of `W`, `E`); zero-knowledge comes from running it only on an
//! accumulator that was masked by folding with a random instance.

use crate::{fs_transcript::Transcript, ipa, sumcheck};
use alloc::vec::Vec;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core_r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness, SparseMatrix};
use llull_folder::CommitmentKey;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpartanProof<C: CurveGroup> {
    pub r_w: C::ScalarField,
    pub r_e: C::ScalarField,
    pub outer: Vec<C::ScalarField>,
    /// `(A·Z)(r_x), (B·Z)(r_x), (C·Z)(r_x), E(r_x)`.
    pub claims: Vec<C::ScalarField>,
    pub ipa_e: ipa::IpaProof<C>,
    pub inner: Vec<C::ScalarField>,
    /// `W(r_y[1..])`.
    pub eval_w: C::ScalarField,
    pub ipa_w: ipa::IpaProof<C>,
}

/// Padded dimensions: `2^log_m` rows; `Z = (W ‖ (u, x))` with `2^log_n` each.
struct Dims {
    log_m: usize,
    log_n: usize,
}

impl Dims {
    fn of<F: PrimeField>(shape: &R1CSShape<F>) -> Self {
        let log2 = |v: usize| v.next_power_of_two().trailing_zeros() as usize;
        Self {
            log_m: log2(shape.num_constraints.max(2)),
            log_n: log2(shape.num_vars.max(shape.num_io + 1).max(2)),
        }
    }
    fn m(&self) -> usize {
        1 << self.log_m
    }
    fn n(&self) -> usize {
        1 << self.log_n
    }
}

/// Column of the engine's `Z = (W, x, u)` inside the padded `(W ‖ (u, x))`.
fn remap<F: PrimeField>(shape: &R1CSShape<F>, n: usize, col: usize) -> usize {
    if col < shape.num_vars {
        col
    } else if col == shape.num_vars + shape.num_io {
        n
    } else {
        n + 1 + (col - shape.num_vars)
    }
}

fn start_transcript<C: CurveGroup>(
    digest: &C::BaseField,
    shape: &R1CSShape<C::ScalarField>,
    u: &RelaxedR1CSInstance<C>,
    r_w: &C::ScalarField,
    r_e: &C::ScalarField,
) -> Transcript {
    let mut t = Transcript::new(b"zeno-llull/spartan/v1");
    t.absorb(b"vk", digest);
    let dims = [shape.num_constraints, shape.num_vars, shape.num_io].map(|v| v as u64);
    t.absorb(b"dims", &dims.to_vec());
    t.absorb(b"instance", u);
    t.absorb(b"r_w", r_w);
    t.absorb(b"r_e", r_e);
    t
}

/// For `matrices = [(M, weight)]`, accumulates `Σ_i row_weight[i] · weight ·
/// M[i][·]` into a table over the padded columns.
fn fold_rows<F: PrimeField>(
    shape: &R1CSShape<F>,
    n: usize,
    matrices: &[(&SparseMatrix<F>, F)],
    row_weight: &[F],
) -> Vec<F> {
    let mut out = alloc::vec![F::zero(); 2 * n];
    for (matrix, weight) in matrices {
        for (i, rw) in row_weight.iter().enumerate().take(matrix.num_rows) {
            let w = *rw * weight;
            for k in matrix.row_ptr[i]..matrix.row_ptr[i + 1] {
                out[remap(shape, n, matrix.col_idx[k])] += w * matrix.values[k];
            }
        }
    }
    out
}

fn padded<F: PrimeField>(v: &[F], len: usize) -> Vec<F> {
    let mut out = v.to_vec();
    out.resize(len, F::zero());
    out
}

/// Proves that `(u, w)` satisfies the relaxed R1CS relation of `shape`.
pub fn prove<C: CurveGroup>(
    ck: &CommitmentKey<C>,
    digest: &C::BaseField,
    shape: &R1CSShape<C::ScalarField>,
    u: &RelaxedR1CSInstance<C>,
    w: &RelaxedR1CSWitness<C>,
) -> SpartanProof<C> {
    let dims = Dims::of(shape);
    let (m, n) = (dims.m(), dims.n());
    assert!(
        ck.len() >= m.max(n),
        "commitment key too short for the SNARK"
    );
    let mut tr = start_transcript(digest, shape, u, &w.r_w, &w.r_e);

    // ---- Outer sum-check: Σ_x eq(τ,x)·(Az·Bz − u·Cz − E)(x) = 0 -----------
    let tau: Vec<C::ScalarField> = tr.challenges(dims.log_m);
    let z = shape.z(&w.w, &u.x, u.u).expect("witness matches the shape");
    let (az, bz, cz) = shape.mul_z(&z);
    let mut tables = [
        sumcheck::eq_table(&tau),
        padded(&az, m),
        padded(&bz, m),
        padded(&cz, m),
        padded(&w.e, m),
    ];
    let relax = u.u;
    let (outer, rx) = sumcheck::prove(
        &mut tables,
        3,
        |v| v[0] * (v[1] * v[2] - relax * v[3] - v[4]),
        &mut tr,
    );
    let claims: Vec<C::ScalarField> = tables[1..].iter().map(|t| t[0]).collect();
    tr.absorb(b"outer-claims", &claims);

    // ---- Opening of E at r_x ---------------------------------------------
    let eq_rx = sumcheck::eq_table(&rx);
    let ipa_e = ipa::prove(&mut tr, &ck.gens[..m], ck.h, padded(&w.e, m), eq_rx.clone());

    // ---- Inner sum-check: Σ_y (A + ρB + ρ²C)(r_x, y)·Z(y) = v_A + ρv_B + ρ²v_C
    let rho: C::ScalarField = tr.challenge();
    let combined = fold_rows(
        shape,
        n,
        &[
            (&shape.a, C::ScalarField::from(1u64)),
            (&shape.b, rho),
            (&shape.c, rho * rho),
        ],
        &eq_rx,
    );
    let mut z_padded = padded(&w.w, n);
    z_padded.push(u.u);
    z_padded.extend_from_slice(&u.x);
    z_padded.resize(2 * n, Zero::zero());
    let mut tables = [combined, z_padded];
    let (inner, ry) = sumcheck::prove(&mut tables, 2, |v| v[0] * v[1], &mut tr);

    // ---- Opening of W at r_y[1..] ------------------------------------------
    let eq_ry = sumcheck::eq_table(&ry[1..]);
    let w_padded = padded(&w.w, n);
    let eval_w = w_padded
        .iter()
        .zip(&eq_ry)
        .fold(C::ScalarField::zero(), |acc, (a, b)| acc + *a * b);
    tr.absorb(b"eval-w", &eval_w);
    let ipa_w = ipa::prove(&mut tr, &ck.gens[..n], ck.h, w_padded, eq_ry);

    SpartanProof {
        r_w: w.r_w,
        r_e: w.r_e,
        outer,
        claims,
        ipa_e,
        inner,
        eval_w,
        ipa_w,
    }
}

/// Verifies a proof for the instance `u`. Runs in `O(nnz + n)` field and
/// group operations, with no preprocessing.
pub fn verify<C: CurveGroup>(
    ck: &CommitmentKey<C>,
    digest: &C::BaseField,
    shape: &R1CSShape<C::ScalarField>,
    u: &RelaxedR1CSInstance<C>,
    proof: &SpartanProof<C>,
) -> bool {
    let dims = Dims::of(shape);
    let (m, n) = (dims.m(), dims.n());
    if ck.len() < m.max(n) || u.x.len() != shape.num_io || proof.claims.len() != 4 {
        return false;
    }
    let mut tr = start_transcript(digest, shape, u, &proof.r_w, &proof.r_e);

    // Outer sum-check.
    let tau: Vec<C::ScalarField> = tr.challenges(dims.log_m);
    let Some((claim, rx)) = sumcheck::verify(Zero::zero(), dims.log_m, 3, &proof.outer, &mut tr)
    else {
        return false;
    };
    let (va, vb, vc, ve) = (
        proof.claims[0],
        proof.claims[1],
        proof.claims[2],
        proof.claims[3],
    );
    let eq_tau_rx = tau
        .iter()
        .zip(&rx)
        .fold(C::ScalarField::from(1u64), |acc, (t, r)| {
            acc * (*t * r + (C::ScalarField::from(1u64) - t) * (C::ScalarField::from(1u64) - r))
        });
    if claim != eq_tau_rx * (va * vb - u.u * vc - ve) {
        return false;
    }
    tr.absorb(b"outer-claims", &proof.claims);

    // E(r_x) against comm_E.
    let eq_rx = sumcheck::eq_table(&rx);
    let p_e = u.comm_e - ck.h * proof.r_e;
    if !ipa::verify(&mut tr, &ck.gens[..m], ck.h, p_e, &eq_rx, ve, &proof.ipa_e) {
        return false;
    }

    // Inner sum-check.
    let rho: C::ScalarField = tr.challenge();
    let Some((claim, ry)) = sumcheck::verify(
        va + rho * vb + rho * rho * vc,
        dims.log_n + 1,
        2,
        &proof.inner,
        &mut tr,
    ) else {
        return false;
    };
    // (A + ρB + ρ²C)(r_x, r_y), evaluated directly from the sparse matrices.
    let eq_ry_full = sumcheck::eq_table(&ry);
    let combined = fold_rows(
        shape,
        n,
        &[
            (&shape.a, C::ScalarField::from(1u64)),
            (&shape.b, rho),
            (&shape.c, rho * rho),
        ],
        &eq_rx,
    );
    let matrix_eval = combined
        .iter()
        .zip(&eq_ry_full)
        .fold(C::ScalarField::zero(), |acc, (a, b)| acc + *a * b);
    // Z(r_y) = (1 − r_y0)·W(r_y') + r_y0·IO(r_y'), with IO = (u, x, 0, …).
    let tail = &ry[1..];
    let io_eval = core::iter::once(&u.u)
        .chain(&u.x)
        .enumerate()
        .fold(C::ScalarField::zero(), |acc, (i, v)| {
            acc + *v * sumcheck::eq_at(tail, i)
        });
    let z_eval = (C::ScalarField::from(1u64) - ry[0]) * proof.eval_w + ry[0] * io_eval;
    if claim != matrix_eval * z_eval {
        return false;
    }

    // W(r_y') against comm_W.
    tr.absorb(b"eval-w", &proof.eval_w);
    let eq_ry = sumcheck::eq_table(tail);
    let p_w = u.comm_w - ck.h * proof.r_w;
    ipa::verify(
        &mut tr,
        &ck.gens[..n],
        ck.h,
        p_w,
        &eq_ry,
        proof.eval_w,
        &proof.ipa_w,
    )
}
