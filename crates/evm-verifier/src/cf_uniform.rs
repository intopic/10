//! The CycleFold matrices from their uniform structure.
//!
//! The CycleFold circuit ([`zeno_ivc::cyclefold::circuit`]) lays its witness
//! and constraints out by type: row `ρ·S + j` is constraint type `ρ` of
//! iteration `j`, column `κ·S + j` is variable type `κ` of iteration `j`
//! (`S = CF_SLOTS` slots, iterations `j < steps`), and the remaining
//! constraints and variables follow the uniform blocks. Every iteration has
//! the same constraints up to the slot, so each matrix is a sum of a few
//! *records*:
//!
//! | kind | entries `(row, column)` for `j` in | value |
//! |---|---|---|
//! | `Same(ρ, κ)` | `(ρS + j, κS + j)`, `0 ≤ j < steps` | `v` |
//! | `Prev(ρ, κ)` | `(ρS + j, κS + j − 1)`, `1 ≤ j < steps` | `v` |
//! | `Fixed(ρ, c)` | `(ρS + j, c)`, `0 ≤ j < steps` | `v` |
//! | `Explicit(r, c)` | `(r, c)` | `v` |
//! | `Pack(r, κ)` | `(r, κS + j)`, `0 ≤ j < steps` | `v·2^(steps − j)` |
//!
//! with columns in the padded `Z = (W ‖ (u, x))` of length `2n`. The
//! records are *derived* from the circuit's matrices (a template read off one
//! slot, the differences as explicit entries) and checked to reproduce them
//! exactly, so nothing relies on the description of the layout above.
//!
//! The verifier evaluates `(A + ρB + ρ²C)(r_x, r_y)` from them with tables
//! over the slot bits and the type bits only: with `X = eq(r_x,lo, ·)`,
//! `Y = eq(r_y,lo, ·)` (`S` entries each) and `H_x`, `H_y` over the high bits,
//! the sums over slots reduce to `D_0 = Σ_j X_j·Y_j`, `D_1 = Σ_j X_j·Y_(j−1)`,
//! `Σ_j X_j` and `Σ_j 2^(steps−j)·Y_j`. The same `X`, `Y`, `H_x` and `H_y` are
//! the Hyrax column and row weights of `E` and `W` (`S = CF_COLUMNS`), so the
//! EVM computes no table of more than `S` entries.

use crate::{word, Word};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use ark_bn254::Fq;
use ark_ff::{AdditiveGroup, Field, One, Zero};
use core_r1cs::{
    mle::{log2_ceil, padded_column},
    R1CSShape,
};
use sha3::{Digest, Keccak256};
use zeno_ivc::cyclefold::{
    circuit::{CF_SLOTS, CF_UNIFORM_TYPES},
    hyrax::eq_table,
    T_BITS,
};

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

/// Every non-zero entry `(matrix, row, column in the padded Z, value)`.
pub fn entries(shape: &R1CSShape<Fq>) -> Vec<(usize, usize, usize, Fq)> {
    let n = 1 << CfDims::of(shape).log_n;
    let mut out = Vec::new();
    for (k, m) in [&shape.a, &shape.b, &shape.c].iter().enumerate() {
        for row in 0..m.num_rows {
            for e in m.row_ptr[row]..m.row_ptr[row + 1] {
                out.push((k, row, padded_column(shape, n, m.col_idx[e]), m.values[e]));
            }
        }
    }
    out.sort_by_key(|&(k, row, col, _)| (row, k, col));
    out
}

/// What a record repeats over the slots (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Same = 0,
    Prev = 1,
    Fixed = 2,
    Explicit = 3,
    Pack = 4,
}

/// One record: `kind`, `matrix` (0, 1, 2 for A, B, C), the index of its value
/// and its two operands (a row type or a row, a column type or a column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    pub kind: Kind,
    pub matrix: usize,
    pub a: usize,
    pub b: usize,
    pub value: usize,
}

/// The CycleFold matrices as records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfUniform {
    pub dims: CfDims,
    pub num_io: usize,
    pub steps: usize,
    pub values: Vec<Fq>,
    pub records: Vec<Record>,
}

type EntryMap = BTreeMap<(usize, usize, usize), Fq>;

fn add_entry(map: &mut EntryMap, key: (usize, usize, usize), v: Fq) {
    let e = map.entry(key).or_insert(Fq::zero());
    *e += v;
    if e.is_zero() {
        map.remove(&key);
    }
}

impl CfUniform {
    pub const LOG_SLOTS: usize = CF_SLOTS.trailing_zeros() as usize;

    /// Derives the records of a CycleFold circuit and checks that they
    /// reproduce its matrices; `None` if the circuit does not have the
    /// layout's dimensions.
    pub fn from_shape(shape: &R1CSShape<Fq>) -> Option<Self> {
        let s = CF_SLOTS;
        let (steps, types) = (T_BITS, CF_UNIFORM_TYPES);
        let dims = CfDims::of(shape);
        let n = 1 << dims.log_n;
        if steps < 3
            || steps >= s
            || dims.log_m <= Self::LOG_SLOTS
            || dims.log_n <= Self::LOG_SLOTS
            || types * s > n.min(1 << dims.log_m)
            || shape.num_io + 1 > s
        {
            return None;
        }
        let mut actual = EntryMap::new();
        for (k, row, col, v) in entries(shape) {
            add_entry(&mut actual, (k, row, col), v);
        }

        // The template: the entries of slot 1 of every uniform row type.
        let mut template: Vec<(Kind, usize, usize, usize, Fq)> = Vec::new();
        for (&(k, row, col), &v) in &actual {
            if row >= types * s || row % s != 1 {
                continue;
            }
            let rt = row / s;
            if col < types * s {
                match col % s {
                    1 => template.push((Kind::Same, k, rt, col / s, v)),
                    0 => template.push((Kind::Prev, k, rt, col / s, v)),
                    _ => {}
                }
            } else {
                template.push((Kind::Fixed, k, rt, col, v));
            }
        }
        let mut uniform = Self {
            dims,
            num_io: shape.num_io,
            steps,
            values: Vec::new(),
            records: Vec::new(),
        };
        for &(kind, k, a, b, v) in &template {
            uniform.push(kind, k, a, b, v);
        }

        // Whatever the template does not produce is explicit, except whole
        // packed sums `Σ_j c·2^(steps−j)·Z[κS + j]` in the remaining rows.
        let mut rest = actual.clone();
        for (key, v) in uniform.expand() {
            add_entry(&mut rest, key, -v);
        }
        let mut packs = Vec::new();
        let rows: Vec<(usize, usize)> = {
            let mut r: Vec<_> = rest.keys().map(|&(k, row, _)| (k, row)).collect();
            r.dedup();
            r
        };
        let top = Fq::from(2u64).pow([steps as u64]);
        for (k, row) in rows {
            if row < types * s {
                continue;
            }
            for ct in 0..types {
                let Some(&v0) = rest.get(&(k, row, ct * s)) else {
                    continue;
                };
                let c = v0 * top.inverse().expect("nonzero");
                let mut w = top;
                let full = (0..steps).all(|j| {
                    let ok = rest.get(&(k, row, ct * s + j)) == Some(&(c * w));
                    w *= Fq::from(2u64).inverse().expect("odd field");
                    ok
                });
                if full {
                    packs.push((k, row, ct, c));
                }
            }
        }
        for &(k, row, ct, c) in &packs {
            uniform.push(Kind::Pack, k, row, ct, c);
        }
        let mut rest = actual.clone();
        for (key, v) in uniform.expand() {
            add_entry(&mut rest, key, -v);
        }
        for (&(k, row, col), &v) in &rest {
            uniform.push(Kind::Explicit, k, row, col, v);
        }
        uniform.records.sort();

        // The records reproduce the matrices exactly.
        let mut check = EntryMap::new();
        for (key, v) in uniform.expand() {
            add_entry(&mut check, key, v);
        }
        (check == actual).then_some(uniform)
    }

    fn push(&mut self, kind: Kind, matrix: usize, a: usize, b: usize, v: Fq) {
        let value = match self.values.iter().position(|x| *x == v) {
            Some(i) => i,
            None => {
                self.values.push(v);
                self.values.len() - 1
            }
        };
        self.records.push(Record {
            kind,
            matrix,
            a,
            b,
            value,
        });
    }

    /// Every entry the records stand for (with repetitions).
    pub fn expand(&self) -> Vec<((usize, usize, usize), Fq)> {
        let s = CF_SLOTS;
        let half = Fq::from(2u64).inverse().expect("odd field");
        let mut out = Vec::new();
        for r in &self.records {
            let (k, a, b, v) = (r.matrix, r.a, r.b, self.values[r.value]);
            match r.kind {
                Kind::Same => {
                    out.extend((0..self.steps).map(|j| ((k, a * s + j, b * s + j), v)));
                }
                Kind::Prev => {
                    out.extend((1..self.steps).map(|j| ((k, a * s + j, b * s + j - 1), v)));
                }
                Kind::Fixed => out.extend((0..self.steps).map(|j| ((k, a * s + j, b), v))),
                Kind::Explicit => out.push(((k, a, b), v)),
                Kind::Pack => {
                    let mut w = v * Fq::from(2u64).pow([self.steps as u64]);
                    for j in 0..self.steps {
                        out.push(((k, a, b * s + j), w));
                        w *= half;
                    }
                }
            }
        }
        out
    }

    /// `(A + ρB + ρ²C)(r_x, r_y)` over the padded `Z`, from the records.
    pub fn eval(&self, rho: Fq, rx: &[Fq], ry: &[Fq]) -> Fq {
        let l = Self::LOG_SLOTS;
        let CfDims { log_m, log_n } = self.dims;
        assert!(rx.len() == log_m && ry.len() == log_n + 1);
        let (hx, x) = (eq_table(&rx[..log_m - l]), eq_table(&rx[log_m - l..]));
        let (hy, y) = (
            eq_table(&ry[1..1 + log_n - l]),
            eq_table(&ry[1 + log_n - l..]),
        );
        let (ry0, w0) = (ry[0], Fq::one() - ry[0]);
        let steps = self.steps;
        let d0: Fq = (0..steps).map(|j| x[j] * y[j]).sum();
        let d1: Fq = (1..steps).map(|j| x[j] * y[j - 1]).sum();
        let sx: Fq = x[..steps].iter().sum();
        let mut pack = Fq::zero();
        let mut w = Fq::from(2u64);
        for j in (0..steps).rev() {
            pack += w * y[j];
            w.double_in_place();
        }
        let mask = (1 << log_n) - 1;
        let col = |c: usize| {
            let f = if c >> log_n == 0 { w0 } else { ry0 };
            let rest = c & mask;
            f * hy[rest >> l] * y[rest & (CF_SLOTS - 1)]
        };
        let row = |r: usize| hx[r >> l] * x[r & (CF_SLOTS - 1)];
        let powers = [Fq::one(), rho, rho * rho];
        self.records
            .iter()
            .map(|r| {
                let (a, b) = (r.a, r.b);
                let term = match r.kind {
                    Kind::Same => hx[a] * w0 * hy[b] * d0,
                    Kind::Prev => hx[a] * w0 * hy[b] * d1,
                    Kind::Fixed => hx[a] * sx * col(b),
                    Kind::Explicit => row(a) * col(b),
                    Kind::Pack => row(a) * w0 * hy[b] * pack,
                };
                powers[r.matrix] * self.values[r.value] * term
            })
            .sum()
    }

    /// The encoding read by `ZenoRecursiveVerifier.sol`:
    ///
    /// * a 32-byte header: `log_m`, `log_n`, `num_io`, `log2(S)`, `steps`
    ///   (one byte each), the numbers of values and of records (two bytes
    ///   each, big-endian), then zeros;
    /// * the values, 32 bytes each (big-endian `Fq`);
    /// * the records, 6 bytes each: `kind·4 + matrix`, the value index, then
    ///   `a` and `b` (two bytes each, big-endian).
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.values.len() < 256 && self.records.len() < 1 << 16);
        let mut data = alloc::vec![0u8; 32];
        data[0] = self.dims.log_m as u8;
        data[1] = self.dims.log_n as u8;
        data[2] = self.num_io as u8;
        data[3] = Self::LOG_SLOTS as u8;
        data[4] = self.steps as u8;
        data[5..7].copy_from_slice(&(self.values.len() as u16).to_be_bytes());
        data[7..9].copy_from_slice(&(self.records.len() as u16).to_be_bytes());
        for v in &self.values {
            data.extend_from_slice(&word(v));
        }
        for r in &self.records {
            data.push(((r.kind as usize) << 2 | r.matrix) as u8);
            data.push(r.value as u8);
            data.extend_from_slice(&(r.a as u16).to_be_bytes());
            data.extend_from_slice(&(r.b as u16).to_be_bytes());
        }
        data
    }

    /// `keccak256` of [`Self::encode`]: the CycleFold part of the system id.
    pub fn hash(&self) -> Word {
        Keccak256::digest(self.encode()).into()
    }

    /// The Solidity library `contracts/ZenoCycleFoldShape.sol` holding the
    /// encoding and its hash.
    pub fn solidity_library(&self) -> String {
        let hex =
            |bytes: &[u8]| -> String { bytes.iter().map(|b| alloc::format!("{b:02x}")).collect() };
        let data = self.encode();
        let lines: Vec<String> = data
            .chunks(48)
            .map(|chunk| alloc::format!("        hex\"{}\"", hex(chunk)))
            .collect();
        let lines = lines.join("\n");
        alloc::format!(
            "// SPDX-License-Identifier: UNLICENSED\n\
             // Generated by `evm_verifier::cf_uniform::CfUniform::solidity_library`:\n\
             // `cargo test -p evm-verifier --test cf_uniform` checks it, and rewrites\n\
             // it with ZENO_WRITE_CF_SHAPE=1. Do not edit.\n\
             pragma solidity ^0.8.24;\n\
             \n\
             /// The matrices of the CycleFold circuit over BN254 ({m} constraints in\n\
             /// 2^{log_m} rows, {w} witness variables in 2^{log_n} columns), as the\n\
             /// {r} records of `evm-verifier::cf_uniform` ({b} bytes).\n\
             library ZenoCycleFoldShape {{\n    \
             bytes internal constant DATA =\n{lines};\n    \
             /// `keccak256(DATA)`, the CycleFold part of every system id.\n    \
             bytes32 internal constant HASH = 0x{h};\n\
             }}\n",
            m = self.expand_rows(),
            log_m = self.dims.log_m,
            w = self.expand_cols(),
            log_n = self.dims.log_n,
            r = self.records.len(),
            b = data.len(),
            lines = lines,
            h = hex(&self.hash()),
        )
    }

    /// One more than the largest row with an entry.
    fn expand_rows(&self) -> usize {
        self.expand()
            .iter()
            .map(|((_, r, _), _)| r + 1)
            .max()
            .unwrap_or(0)
    }

    /// One more than the largest witness column with an entry.
    fn expand_cols(&self) -> usize {
        let n = 1 << self.dims.log_n;
        self.expand()
            .iter()
            .filter(|((_, _, c), _)| *c < n)
            .map(|((_, _, c), _)| c + 1)
            .max()
            .unwrap_or(0)
    }
}

/// The records of the CycleFold circuit over BN254.
pub fn bn254() -> CfUniform {
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
    use core_r1cs::ark_bridge::shape_from_cs;
    use zeno_ivc::cyclefold::CycleFoldCircuit;
    let cs = ConstraintSystem::<Fq>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    CycleFoldCircuit::<ark_bn254::g1::Config>::placeholder()
        .synthesize(cs.clone())
        .expect("the CycleFold circuit synthesizes");
    let shape = shape_from_cs(&cs).expect("matrices");
    CfUniform::from_shape(&shape).expect("the CycleFold circuit is uniform")
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn records_evaluate_the_matrices() {
        let u = bn254();
        let shape = {
            use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
            let cs = ConstraintSystem::<Fq>::new_ref();
            cs.set_mode(SynthesisMode::Prove {
                construct_matrices: true,
            });
            zeno_ivc::cyclefold::CycleFoldCircuit::<ark_bn254::g1::Config>::placeholder()
                .synthesize(cs.clone())
                .unwrap();
            core_r1cs::ark_bridge::shape_from_cs(&cs).unwrap()
        };
        let mut rng = test_rng();
        for _ in 0..4 {
            let rho = Fq::rand(&mut rng);
            let rx: Vec<Fq> = (0..u.dims.log_m).map(|_| Fq::rand(&mut rng)).collect();
            let ry: Vec<Fq> = (0..=u.dims.log_n).map(|_| Fq::rand(&mut rng)).collect();
            let (ex, ey) = (eq_table(&rx), eq_table(&ry));
            let powers = [Fq::one(), rho, rho * rho];
            let direct: Fq = entries(&shape)
                .iter()
                .map(|&(k, row, col, v)| powers[k] * v * ex[row] * ey[col])
                .sum();
            assert_eq!(u.eval(rho, &rx, &ry), direct);
        }
        let kinds = |k: Kind| u.records.iter().filter(|r| r.kind == k).count();
        std::println!(
            "{} records ({} same, {} prev, {} fixed, {} explicit, {} packed), {} values, {} bytes, for {} entries",
            u.records.len(),
            kinds(Kind::Same),
            kinds(Kind::Prev),
            kinds(Kind::Fixed),
            kinds(Kind::Explicit),
            kinds(Kind::Pack),
            u.values.len(),
            u.encode().len(),
            entries(&shape).len()
        );
        // The uniform blocks are captured by the template: only the first
        // iteration and the non-uniform rows are explicit.
        assert!(kinds(Kind::Explicit) < 256 && kinds(Kind::Pack) == 1);
    }

    #[test]
    fn a_changed_matrix_is_not_described() {
        // The derivation reproduces the matrices exactly, so it also follows
        // any change; a record set derived elsewhere does not match.
        let u = bn254();
        let mut other = u.clone();
        other.values[0] += Fq::one();
        assert_ne!(other.hash(), u.hash());
        let mut rng = test_rng();
        let rho = Fq::rand(&mut rng);
        let rx: Vec<Fq> = (0..u.dims.log_m).map(|_| Fq::rand(&mut rng)).collect();
        let ry: Vec<Fq> = (0..=u.dims.log_n).map(|_| Fq::rand(&mut rng)).collect();
        assert_ne!(other.eval(rho, &rx, &ry), u.eval(rho, &rx, &ry));
    }
}
