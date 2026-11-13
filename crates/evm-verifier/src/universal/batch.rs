//! The universal decider for several accumulators of different circuits in
//! one argument.
//!
//! All circuit keys are preprocessed with the *same* dimensions
//! ([`CircuitKey::preprocess_with_dims`]), so every table has the same size
//! and every step of [`super::decider`] runs once for all instances, their
//! claims combined with powers of a fresh challenge:
//!
//! 1. outer sum-check of `Σ_i α^i·eq(τ,x)·(A_iz_i·B_iz_i − u_i·C_iz_i − E_i)(x)`;
//! 2. inner sum-check of `Σ_i α'^i·M_i(r_x, y)·Z_i(y)`;
//! 3. lookups of `eq(r_x, ·)` and `eq(r_y, ·)` (shared tables) at every
//!    circuit's matrix indices;
//! 4. one sum-check over the matrix entries, one per lookup table;
//! 5. one joint HyperKZG opening of five claims, each holding the polynomials
//!    of every instance at the same point.
//!
//! The proof is about the size of a single-instance proof (one set of
//! sum-check messages and of folded commitments), not their sum.

use super::{
    decider::{
        index_mle, inverses, padded, summand_k, summand_table, Challenges, CircuitKey, Dims,
    },
    hyperkzg::{self, mle_eval, Claim, HyperKzgProof},
    transcript::KeccakTranscript,
};
use crate::{point_words, word, EvmParams, Word};
use alloc::vec::Vec;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{One, Zero};
use core_r1cs::{RelaxedR1CSInstance, RelaxedR1CSWitness};
use decider_zk::sumcheck::{self, eq_points, eq_table};

/// Domain separator of the batched decider's transcript.
pub const DOMAIN: &[u8] = b"zeno-llull/universal-batch/v1";

/// The batched decider proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchProof {
    /// `(r_W, r_E)` per instance.
    pub blinds: Vec<[Fr; 2]>,
    pub outer: Vec<Fr>,
    /// Per instance: `(Az)(r_x), (Bz)(r_x), (Cz)(r_x), E(r_x)`.
    pub claims: Vec<[Fr; 4]>,
    pub inner: Vec<Fr>,
    /// Per instance: `(A+ρB+ρ²C)(r_x, r_y)` and `W(r_y[1..])`.
    pub v: Vec<[Fr; 2]>,
    /// Per instance: commitments to `e_row, e_col`, then to `h1_row, h1_col,
    /// h2_row, h2_col`.
    pub comms: Vec<[G1; 6]>,
    /// Per instance: the two LogUp sums.
    pub sums: Vec<[Fr; 2]>,
    pub sc_k: Vec<Fr>,
    /// Per instance: `val_A, val_B, val_C, row, col, e_row, e_col, h1_row,
    /// h1_col` at `r_k`.
    pub evals_k: Vec<[Fr; 9]>,
    pub sc_m: Vec<Fr>,
    /// Per instance: `h2_row, count_row` at `r_j`.
    pub evals_m: Vec<[Fr; 2]>,
    pub sc_z: Vec<Fr>,
    /// Per instance: `h2_col, count_col` at `r_z`.
    pub evals_z: Vec<[Fr; 2]>,
    pub openings: HyperKzgProof,
}

impl BatchProof {
    /// The proof as the flat word array the contract parses, in protocol
    /// order; every length is determined by the dimensions and the number of
    /// instances.
    pub fn words(&self) -> Vec<Word> {
        let scalars = |out: &mut Vec<Word>, v: &[Fr]| out.extend(v.iter().map(word));
        let points = |out: &mut Vec<Word>, v: &[G1]| out.extend(v.iter().flat_map(point_words));
        let mut w = Vec::new();
        for b in &self.blinds {
            scalars(&mut w, b);
        }
        scalars(&mut w, &self.outer);
        for c in &self.claims {
            scalars(&mut w, c);
        }
        scalars(&mut w, &self.inner);
        for v in &self.v {
            scalars(&mut w, v);
        }
        for c in &self.comms {
            points(&mut w, &c[..2]);
        }
        for c in &self.comms {
            points(&mut w, &c[2..]);
        }
        for s in &self.sums {
            scalars(&mut w, s);
        }
        scalars(&mut w, &self.sc_k);
        for e in &self.evals_k {
            scalars(&mut w, e);
        }
        scalars(&mut w, &self.sc_m);
        for e in &self.evals_m {
            scalars(&mut w, e);
        }
        scalars(&mut w, &self.sc_z);
        for e in &self.evals_z {
            scalars(&mut w, e);
        }
        let o = &self.openings;
        for c in &o.comms {
            points(&mut w, c);
        }
        for j in 0..o.y_pos.len() {
            scalars(&mut w, &o.y_pos[j]);
            scalars(&mut w, &o.y_neg[j]);
            scalars(&mut w, &o.y_sq[j]);
        }
        points(&mut w, &o.pi);
        w
    }
}

/// One instance to decide: its circuit's parameters and key, and the
/// accumulator.
pub struct Item<'a> {
    pub params: &'a EvmParams,
    pub key: &'a CircuitKey,
    pub acc: &'a RelaxedR1CSInstance<G1>,
}

fn powers(base: Fr, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    let mut p = Fr::one();
    for _ in 0..n {
        out.push(p);
        p *= base;
    }
    out
}

/// The common dimensions, if every key has the same ones and every
/// commitment key the same powers and `[τ]₂`.
fn common_dims(items: &[Item]) -> Option<Dims> {
    let first = items.first()?;
    let dims = first.key.dims;
    let ok = items.iter().all(|it| {
        it.key.dims == dims
            && it.params.tau_g2.is_some()
            && it.params.tau_g2 == first.params.tau_g2
            && it.acc.x.len() == it.params.shape.num_io
            && it.params.ck.len() == first.params.ck.len()
    });
    ok.then_some(dims)
}

fn start(items: &[Item], blinds: &[[Fr; 2]]) -> KeccakTranscript {
    let mut tr = KeccakTranscript::new(DOMAIN);
    let mut words = alloc::vec![word(&Fr::from(items.len() as u64))];
    for (it, b) in items.iter().zip(blinds) {
        words.push(it.params.vk);
        words.push(it.key.digest());
        words.extend(point_words(&it.acc.comm_e));
        words.push(word(&it.acc.u));
        words.extend(point_words(&it.acc.comm_w));
        words.extend(it.acc.x.iter().map(word));
        words.push(word(&b[0]));
        words.push(word(&b[1]));
    }
    tr.absorb_words(&words);
    tr
}

/// Proves that every `(item, witness)` satisfies its circuit's relaxed R1CS
/// relation. Panics if the keys do not share dimensions and reference string.
pub fn prove(items: &[Item], witnesses: &[&RelaxedR1CSWitness<G1>]) -> BatchProof {
    let dims = common_dims(items).expect("keys must share dimensions and reference string");
    assert_eq!(items.len(), witnesses.len());
    let ck = &items[0].params.ck;
    assert!(
        items.iter().all(|it| it.params.ck.gens == ck.gens),
        "keys must use the same powers"
    );
    let n_inst = items.len();
    let (m, n, z_len, k_len) = (dims.m(), dims.n(), dims.z(), dims.k());
    let commit = |v: &[Fr]| ck.commit(v, Fr::zero());
    let blinds: Vec<[Fr; 2]> = witnesses.iter().map(|w| [w.r_w, w.r_e]).collect();
    let mut tr = start(items, &blinds);

    // ---- 1. Outer sum-check ----------------------------------------------
    let tau = tr.challenges(dims.log_m);
    let alpha = powers(tr.challenge(), n_inst);
    let mut tables = alloc::vec![eq_table(&tau)];
    let mut es = Vec::with_capacity(n_inst);
    for (it, w) in items.iter().zip(witnesses) {
        let z = it
            .params
            .shape
            .z(&w.w, &it.acc.x, it.acc.u)
            .expect("witness matches the shape");
        let (az, bz, cz) = it.params.shape.mul_z(&z);
        let e = padded(&w.e, m);
        tables.extend([padded(&az, m), padded(&bz, m), padded(&cz, m), e.clone()]);
        es.push(e);
    }
    let us: Vec<Fr> = items.iter().map(|it| it.acc.u).collect();
    let (outer, rx) = sumcheck::prove(
        &mut tables,
        3,
        |v| {
            v[0] * (0..n_inst).fold(Fr::zero(), |acc, i| {
                let b = 1 + 4 * i;
                acc + alpha[i] * (v[b] * v[b + 1] - us[i] * v[b + 2] - v[b + 3])
            })
        },
        &mut tr,
    );
    let claims: Vec<[Fr; 4]> = (0..n_inst)
        .map(|i| core::array::from_fn(|j| tables[1 + 4 * i + j][0]))
        .collect();
    tr.absorb_scalars(&claims.concat());

    // ---- 2. Inner sum-check ----------------------------------------------
    let rho = tr.challenge();
    let alpha2 = powers(tr.challenge(), n_inst);
    let rho2 = rho * rho;
    let eq_rx = eq_table(&rx);
    let mut tables = Vec::with_capacity(2 * n_inst);
    let mut val_rhos = Vec::with_capacity(n_inst);
    let mut ws = Vec::with_capacity(n_inst);
    for (it, w) in items.iter().zip(witnesses) {
        let key = it.key;
        let val_rho: Vec<Fr> = (0..k_len)
            .map(|k| key.val[0][k] + rho * key.val[1][k] + rho2 * key.val[2][k])
            .collect();
        let mut combined = alloc::vec![Fr::zero(); z_len];
        for k in 0..k_len {
            combined[key.col_idx[k]] += eq_rx[key.row_idx[k]] * val_rho[k];
        }
        let w_padded = padded(&w.w, n);
        let mut z_padded = w_padded.clone();
        z_padded.push(it.acc.u);
        z_padded.extend_from_slice(&it.acc.x);
        z_padded.resize(z_len, Fr::zero());
        tables.extend([combined, z_padded]);
        val_rhos.push(val_rho);
        ws.push(w_padded);
    }
    let (inner, ry) = sumcheck::prove(
        &mut tables,
        2,
        |v| {
            (0..n_inst).fold(Fr::zero(), |acc, i| {
                acc + alpha2[i] * v[2 * i] * v[2 * i + 1]
            })
        },
        &mut tr,
    );
    let v: Vec<[Fr; 2]> = (0..n_inst)
        .map(|i| [tables[2 * i][0], mle_eval(&ws[i], &ry[1..])])
        .collect();
    tr.absorb_scalars(&v.concat());

    // ---- 3. Lookups --------------------------------------------------------
    let eq_ry = eq_table(&ry);
    let mut e_rows = Vec::with_capacity(n_inst);
    let mut e_cols = Vec::with_capacity(n_inst);
    let mut first = Vec::with_capacity(2 * n_inst);
    for it in items {
        let e_row: Vec<Fr> = it.key.row_idx.iter().map(|i| eq_rx[*i]).collect();
        let e_col: Vec<Fr> = it.key.col_idx.iter().map(|i| eq_ry[*i]).collect();
        first.extend([commit(&e_row), commit(&e_col)]);
        e_rows.push(e_row);
        e_cols.push(e_col);
    }
    tr.absorb_points(&first);
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
    let mut h = Vec::with_capacity(n_inst); // [h1r, h1c, h2r, h2c] per instance
    let mut comms = Vec::with_capacity(n_inst);
    let mut second = Vec::with_capacity(4 * n_inst);
    for (i, it) in items.iter().enumerate() {
        let key = it.key;
        let polys = [
            lookup(&key.row, &e_rows[i]),
            lookup(&key.col, &e_cols[i]),
            table(&eq_rx, &key.count_row),
            table(&eq_ry, &key.count_col),
        ];
        let c: [G1; 4] = core::array::from_fn(|j| commit(&polys[j]));
        second.extend(c);
        comms.push([first[2 * i], first[2 * i + 1], c[0], c[1], c[2], c[3]]);
        h.push(polys);
    }
    tr.absorb_points(&second);
    let sums: Vec<[Fr; 2]> = h
        .iter()
        .map(|p| [p[0].iter().sum(), p[1].iter().sum()])
        .collect();
    tr.absorb_scalars(&sums.concat());

    // ---- 4. Sum-check over the matrix entries ------------------------------
    let delta = tr.challenge();
    let delta_b = powers(tr.challenge(), n_inst);
    let tau_k = tr.challenges(dims.log_k);
    let mut tables = alloc::vec![eq_table(&tau_k)];
    for (i, it) in items.iter().enumerate() {
        tables.extend([
            val_rhos[i].clone(),
            e_rows[i].clone(),
            e_cols[i].clone(),
            h[i][0].clone(),
            h[i][1].clone(),
            it.key.row.clone(),
            it.key.col.clone(),
        ]);
    }
    let (sc_k, rk) = sumcheck::prove(
        &mut tables,
        3,
        |v| {
            (0..n_inst).fold(Fr::zero(), |acc, i| {
                let b = 1 + 7 * i;
                let args = [
                    v[b],
                    v[b + 1],
                    v[b + 2],
                    v[b + 3],
                    v[b + 4],
                    v[0],
                    v[b + 5],
                    v[b + 6],
                ];
                acc + delta_b[i] * summand_k(&args, &ch, delta)
            })
        },
        &mut tr,
    );
    let mut polys_k: Vec<&[Fr]> = Vec::with_capacity(9 * n_inst);
    for (i, it) in items.iter().enumerate() {
        let key = it.key;
        polys_k.extend([
            &key.val[0][..],
            &key.val[1][..],
            &key.val[2][..],
            &key.row[..],
            &key.col[..],
            &e_rows[i][..],
            &e_cols[i][..],
            &h[i][0][..],
            &h[i][1][..],
        ]);
    }
    let evals_k: Vec<[Fr; 9]> = (0..n_inst)
        .map(|i| core::array::from_fn(|j| mle_eval(polys_k[9 * i + j], &rk)))
        .collect();
    tr.absorb_scalars(&evals_k.concat());

    // ---- 5. Sum-checks over the two lookup tables ---------------------------
    let ids = |len: usize| (0..len as u64).map(Fr::from).collect::<Vec<_>>();
    let mut table_sumcheck = |log: usize,
                              eq_point: &[Fr],
                              which: usize,
                              counts: &dyn Fn(usize) -> Vec<Fr>|
     -> (Vec<Fr>, Vec<Fr>, Vec<[Fr; 2]>) {
        let delta = tr.challenge();
        let db = powers(tr.challenge(), n_inst);
        let tau = tr.challenges(log);
        let len = 1 << log;
        let mut tables = alloc::vec![eq_table(&tau), ids(len), eq_point.to_vec()];
        for (i, poly) in h.iter().enumerate() {
            tables.extend([poly[which].clone(), counts(i)]);
        }
        let (msgs, r) = sumcheck::prove(
            &mut tables,
            3,
            |v| {
                (0..n_inst).fold(Fr::zero(), |acc, i| {
                    let b = 3 + 2 * i;
                    acc + db[i] * summand_table(&[v[b], v[0], v[1], v[2], v[b + 1]], &ch, delta)
                })
            },
            &mut tr,
        );
        let evals: Vec<[Fr; 2]> = (0..n_inst)
            .map(|i| [tables[3 + 2 * i][0], tables[4 + 2 * i][0]])
            .collect();
        tr.absorb_scalars(&evals.concat());
        (msgs, r, evals)
    };
    let (sc_m, rj, evals_m) =
        table_sumcheck(dims.log_m, &eq_rx, 2, &|i| items[i].key.count_row.clone());
    let (sc_z, rz, evals_z) = table_sumcheck(dims.log_n + 1, &eq_ry, 3, &|i| {
        items[i].key.count_col.clone()
    });

    // ---- 6. One joint opening ----------------------------------------------
    let e_polys: Vec<&[Fr]> = es.iter().map(|e| &e[..]).collect();
    let e_vals: Vec<Fr> = claims.iter().map(|c| c[3]).collect();
    let w_polys: Vec<&[Fr]> = ws.iter().map(|w| &w[..]).collect();
    let w_vals: Vec<Fr> = v.iter().map(|v| v[1]).collect();
    let mut m_polys: Vec<&[Fr]> = Vec::new();
    let mut z_polys: Vec<&[Fr]> = Vec::new();
    for (i, it) in items.iter().enumerate() {
        m_polys.extend([&h[i][2][..], &it.key.count_row[..]]);
        z_polys.extend([&h[i][3][..], &it.key.count_col[..]]);
    }
    let (m_vals, z_vals) = (evals_m.concat(), evals_z.concat());
    let k_vals = evals_k.concat();
    let openings = hyperkzg::prove(
        &mut tr,
        ck,
        &[
            Claim {
                polys: &e_polys,
                point: &rx,
                values: &e_vals,
            },
            Claim {
                polys: &w_polys,
                point: &ry[1..],
                values: &w_vals,
            },
            Claim {
                polys: &polys_k,
                point: &rk,
                values: &k_vals,
            },
            Claim {
                polys: &m_polys,
                point: &rj,
                values: &m_vals,
            },
            Claim {
                polys: &z_polys,
                point: &rz,
                values: &z_vals,
            },
        ],
    );
    BatchProof {
        blinds,
        outer,
        claims,
        inner,
        v,
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

/// Verifies a batched proof up to its pairing equation: returns `(L, R)`
/// with the proof valid iff `e(L, G₂) = e(R, [τ]₂)`, or `None` if any other
/// check fails.
pub fn verify_deferred(items: &[Item], proof: &BatchProof) -> Option<(G1, G1)> {
    let dims = common_dims(items)?;
    let n_inst = items.len();
    let p = proof;
    let shaped = p.blinds.len() == n_inst
        && p.claims.len() == n_inst
        && p.v.len() == n_inst
        && p.comms.len() == n_inst
        && p.sums.len() == n_inst
        && p.evals_k.len() == n_inst
        && p.evals_m.len() == n_inst
        && p.evals_z.len() == n_inst;
    if !shaped {
        return None;
    }
    let mut tr = start(items, &p.blinds);

    // 1. Outer sum-check.
    let tau = tr.challenges(dims.log_m);
    let alpha = powers(tr.challenge(), n_inst);
    let (claim, rx) = sumcheck::verify(Fr::zero(), dims.log_m, 3, &p.outer, &mut tr)?;
    let rhs = (0..n_inst).fold(Fr::zero(), |acc, i| {
        let [va, vb, vc, ve] = p.claims[i];
        acc + alpha[i] * (va * vb - items[i].acc.u * vc - ve)
    });
    if claim != eq_points(&tau, &rx) * rhs {
        return None;
    }
    tr.absorb_scalars(&p.claims.concat());

    // 2. Inner sum-check.
    let rho = tr.challenge();
    let alpha2 = powers(tr.challenge(), n_inst);
    let start_claim = (0..n_inst).fold(Fr::zero(), |acc, i| {
        let [va, vb, vc, _] = p.claims[i];
        acc + alpha2[i] * (va + rho * vb + rho * rho * vc)
    });
    let (claim, ry) = sumcheck::verify(start_claim, dims.log_n + 1, 2, &p.inner, &mut tr)?;
    let tail = &ry[1..];
    let expected = (0..n_inst).fold(Fr::zero(), |acc, i| {
        let acc_i = items[i].acc;
        let io = core::iter::once(&acc_i.u)
            .chain(&acc_i.x)
            .enumerate()
            .fold(Fr::zero(), |s, (j, x)| s + *x * sumcheck::eq_at(tail, j));
        let z = (Fr::one() - ry[0]) * p.v[i][1] + ry[0] * io;
        acc + alpha2[i] * p.v[i][0] * z
    });
    if claim != expected {
        return None;
    }
    tr.absorb_scalars(&p.v.concat());

    // 3. Lookup commitments and sums.
    let first: Vec<G1> = p.comms.iter().flat_map(|c| [c[0], c[1]]).collect();
    tr.absorb_points(&first);
    let ch = Challenges {
        beta: tr.challenge(),
        gamma: tr.challenge(),
    };
    let second: Vec<G1> = p
        .comms
        .iter()
        .flat_map(|c| [c[2], c[3], c[4], c[5]])
        .collect();
    tr.absorb_points(&second);
    tr.absorb_scalars(&p.sums.concat());

    // 4. Sum-check over the matrix entries.
    let delta = tr.challenge();
    let delta_b = powers(tr.challenge(), n_inst);
    let tau_k = tr.challenges(dims.log_k);
    let claim_k = (0..n_inst).fold(Fr::zero(), |acc, i| {
        acc + delta_b[i] * (p.v[i][0] + delta * p.sums[i][0] + delta * delta * p.sums[i][1])
    });
    let (claim, rk) = sumcheck::verify(claim_k, dims.log_k, 3, &p.sc_k, &mut tr)?;
    let eq_k = eq_points(&tau_k, &rk);
    let expected = (0..n_inst).fold(Fr::zero(), |acc, i| {
        let e = &p.evals_k[i];
        let at_rk = [
            e[0] + rho * e[1] + rho * rho * e[2],
            e[5],
            e[6],
            e[7],
            e[8],
            eq_k,
            e[3],
            e[4],
        ];
        acc + delta_b[i] * summand_k(&at_rk, &ch, delta)
    });
    if claim != expected {
        return None;
    }
    tr.absorb_scalars(&p.evals_k.concat());

    // 5. Sum-checks over the two lookup tables.
    let mut table_check =
        |log: usize, which: usize, msgs: &[Fr], evals: &[[Fr; 2]], point: &[Fr]| {
            let delta = tr.challenge();
            let db = powers(tr.challenge(), n_inst);
            let tau = tr.challenges(log);
            let start = (0..n_inst).fold(Fr::zero(), |acc, i| acc + db[i] * p.sums[i][which]);
            let (claim, r) = sumcheck::verify(start, log, 3, msgs, &mut tr)?;
            let (eq_tau, index, eq_pt) = (eq_points(&tau, &r), index_mle(&r), eq_points(point, &r));
            let expected = (0..n_inst).fold(Fr::zero(), |acc, i| {
                acc + db[i]
                    * summand_table(
                        &[evals[i][0], eq_tau, index, eq_pt, evals[i][1]],
                        &ch,
                        delta,
                    )
            });
            if claim != expected {
                return None;
            }
            tr.absorb_scalars(&evals.concat());
            Some(r)
        };
    let rj = table_check(dims.log_m, 0, &p.sc_m, &p.evals_m, &rx)?;
    let rz = table_check(dims.log_n + 1, 1, &p.sc_z, &p.evals_z, &ry)?;

    // 6. The joint opening.
    let mut e_comms = Vec::with_capacity(n_inst);
    let mut w_comms = Vec::with_capacity(n_inst);
    let mut k_comms = Vec::with_capacity(9 * n_inst);
    let mut m_comms = Vec::with_capacity(2 * n_inst);
    let mut z_comms = Vec::with_capacity(2 * n_inst);
    for (i, it) in items.iter().enumerate() {
        let h = it.params.ck.h;
        let k = &it.key.comms;
        let c = &p.comms[i];
        e_comms.push(it.acc.comm_e - h * p.blinds[i][1]);
        w_comms.push(it.acc.comm_w - h * p.blinds[i][0]);
        k_comms.extend([k[2], k[3], k[4], k[0], k[1], c[0], c[1], c[2], c[3]]);
        m_comms.extend([c[4], k[5]]);
        z_comms.extend([c[5], k[6]]);
    }
    let e_vals: Vec<Fr> = p.claims.iter().map(|c| c[3]).collect();
    let w_vals: Vec<Fr> = p.v.iter().map(|v| v[1]).collect();
    let (k_vals, m_vals, z_vals) = (p.evals_k.concat(), p.evals_m.concat(), p.evals_z.concat());
    let claims: [(Vec<G1>, &[Fr], &[Fr]); 5] = [
        (e_comms, &rx, &e_vals),
        (w_comms, tail, &w_vals),
        (k_comms, &rk, &k_vals),
        (m_comms, &rj, &m_vals),
        (z_comms, &rz, &z_vals),
    ];
    hyperkzg::verify(&mut tr, &claims, &p.openings)
}

/// [`verify_deferred`] followed by the pairing check.
pub fn verify(items: &[Item], proof: &BatchProof) -> bool {
    let Some(tau_g2) = items.first().and_then(|it| it.params.tau_g2) else {
        return false;
    };
    verify_deferred(items, proof).is_some_and(|(l, r)| hyperkzg::pairing_check(l, r, tau_g2))
}
