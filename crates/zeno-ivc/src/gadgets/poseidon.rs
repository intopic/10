//! A low-weight Poseidon sponge gadget.
//!
//! It computes exactly the function of arkworks' native `PoseidonSponge`
//! (same duplex logic, rounds and constants; tested against it), but keeps
//! the constraint matrices sparse. In arkworks' gadget the four state
//! elements that skip the S-box in a partial round stay symbolic linear
//! combinations that grow by one term per round, so after 60 partial rounds
//! every S-box input touches ~65 variables (about 29 non-zero entries per
//! constraint). Here the state is re-allocated as fresh witnesses every
//! `FLATTEN_EVERY` partial rounds, and absorbed inputs (often long bit
//! packings) are allocated once before the permutation: about 2.6× fewer
//! non-zero entries for 13% more constraints.

use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, DuplexSpongeMode};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Partial rounds between two re-allocations of the state.
const FLATTEN_EVERY: usize = 8;

pub struct PoseidonVar<F: PrimeField> {
    cs: ConstraintSystemRef<F>,
    params: PoseidonConfig<F>,
    state: Vec<FpVar<F>>,
    mode: DuplexSpongeMode,
    /// State positions absorbed into since the last permutation.
    dirty: Vec<bool>,
}

impl<F: PrimeField> PoseidonVar<F> {
    pub fn new(cs: ConstraintSystemRef<F>, params: &PoseidonConfig<F>) -> Self {
        let width = params.rate + params.capacity;
        Self {
            cs,
            params: params.clone(),
            state: alloc::vec![FpVar::zero(); width],
            mode: DuplexSpongeMode::Absorbing {
                next_absorb_index: 0,
            },
            dirty: alloc::vec![false; width],
        }
    }

    /// A fresh witness equal to `v` (one constraint), unless `v` is constant.
    fn flatten(&self, v: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        if v.is_constant() {
            return Ok(v.clone());
        }
        let w = FpVar::new_witness(self.cs.clone(), || v.value())?;
        w.enforce_equal(v)?;
        Ok(w)
    }

    fn sbox(&self, v: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        v.pow_by_constant([self.params.alpha])
    }

    fn ark_and_mds(
        &self,
        state: &mut [FpVar<F>],
        round: usize,
        full: bool,
    ) -> Result<(), SynthesisError> {
        for (i, s) in state.iter_mut().enumerate() {
            *s += self.params.ark[round][i];
        }
        if full {
            for s in state.iter_mut() {
                *s = self.sbox(s)?;
            }
        } else {
            state[0] = self.sbox(&state[0])?;
        }
        let mixed: Vec<FpVar<F>> = (0..state.len())
            .map(|i| {
                state
                    .iter()
                    .zip(&self.params.mds[i])
                    .fold(FpVar::zero(), |acc, (s, m)| acc + s * *m)
            })
            .collect();
        state.clone_from_slice(&mixed);
        Ok(())
    }

    fn permute(&mut self) -> Result<(), SynthesisError> {
        let mut state = self.state.clone();
        for i in 0..state.len() {
            if self.dirty[i] {
                state[i] = self.flatten(&state[i])?;
            }
        }
        self.dirty.iter_mut().for_each(|d| *d = false);
        let half = self.params.full_rounds / 2;
        let partial = self.params.partial_rounds;
        for round in 0..half {
            self.ark_and_mds(&mut state, round, true)?;
        }
        for (j, round) in (half..half + partial).enumerate() {
            self.ark_and_mds(&mut state, round, false)?;
            if (j + 1) % FLATTEN_EVERY == 0 && j + 1 < partial {
                for s in state.iter_mut() {
                    *s = self.flatten(s)?;
                }
            }
        }
        for round in half + partial..partial + self.params.full_rounds {
            self.ark_and_mds(&mut state, round, true)?;
        }
        self.state = state;
        Ok(())
    }

    fn absorb_internal(
        &mut self,
        mut rate_start: usize,
        elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let (rate, capacity) = (self.params.rate, self.params.capacity);
        let mut remaining = elements;
        loop {
            if rate_start + remaining.len() <= rate {
                for (i, element) in remaining.iter().enumerate() {
                    self.state[capacity + i + rate_start] += element;
                    self.dirty[capacity + i + rate_start] = true;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start + remaining.len(),
                };
                return Ok(());
            }
            let taken = rate - rate_start;
            for (i, element) in remaining.iter().enumerate().take(taken) {
                self.state[capacity + i + rate_start] += element;
                self.dirty[capacity + i + rate_start] = true;
            }
            self.permute()?;
            remaining = &remaining[taken..];
            rate_start = 0;
        }
    }

    fn squeeze_internal(
        &mut self,
        mut rate_start: usize,
        output: &mut [FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let (rate, capacity) = (self.params.rate, self.params.capacity);
        let mut remaining = output;
        loop {
            if rate_start + remaining.len() <= rate {
                let n = remaining.len();
                remaining.clone_from_slice(
                    &self.state[capacity + rate_start..capacity + n + rate_start],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start + n,
                };
                return Ok(());
            }
            let taken = rate - rate_start;
            remaining[..taken].clone_from_slice(
                &self.state[capacity + rate_start..capacity + taken + rate_start],
            );
            remaining = &mut remaining[taken..];
            if !remaining.is_empty() {
                self.permute()?;
            }
            rate_start = 0;
        }
    }

    pub fn absorb(&mut self, input: &[FpVar<F>]) -> Result<(), SynthesisError> {
        if input.is_empty() {
            return Ok(());
        }
        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut index = next_absorb_index;
                if index == self.params.rate {
                    self.permute()?;
                    index = 0;
                }
                self.absorb_internal(index, input)
            }
            DuplexSpongeMode::Squeezing { .. } => self.absorb_internal(0, input),
        }
    }

    pub fn squeeze_field_elements(&mut self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut out = alloc::vec![FpVar::zero(); n];
        match self.mode {
            DuplexSpongeMode::Absorbing { .. } => {
                self.permute()?;
                self.squeeze_internal(0, &mut out)?;
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut index = next_squeeze_index;
                if index == self.params.rate {
                    self.permute()?;
                    index = 0;
                }
                self.squeeze_internal(index, &mut out)?;
            }
        }
        Ok(out)
    }

    /// The first `n` bits of the canonical little-endian decompositions of
    /// squeezed elements, `MODULUS_BIT_SIZE − 1` usable bits per element (as
    /// arkworks' native `squeeze_bits`).
    pub fn squeeze_bits(&mut self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let usable = (F::MODULUS_BIT_SIZE - 1) as usize;
        let elements = self.squeeze_field_elements(n.div_ceil(usable))?;
        let mut bits = Vec::with_capacity(n);
        for e in &elements {
            bits.extend_from_slice(&e.to_bits_le()?[..usable]);
        }
        bits.truncate(n);
        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar,
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        CryptographicSponge,
    };
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
    use ark_std::test_rng;
    use llull_folder::transcript::poseidon_config;

    type F = ark_bn254::Fr;

    fn weight(cs: &ConstraintSystemRef<F>) -> (usize, usize) {
        cs.finalize();
        let m = cs.to_matrices().unwrap();
        (
            m.num_constraints,
            m.a_num_non_zero + m.b_num_non_zero + m.c_num_non_zero,
        )
    }

    #[test]
    fn matches_the_native_sponge_on_every_schedule() {
        let mut rng = test_rng();
        let params = poseidon_config::<F>();
        // Absorb/squeeze schedules crossing the rate boundary both ways.
        let schedules: [&[isize]; 6] = [
            &[1, -1],
            &[4, -1],
            &[5, -2],
            &[9, -1, 3, -1, -128],
            &[0, 2, -5, 7, -1],
            &[13, -300],
        ];
        for schedule in schedules {
            let cs = ConstraintSystem::<F>::new_ref();
            let mut native = PoseidonSponge::new(&params);
            let mut var = PoseidonVar::new(cs.clone(), &params);
            for &op in schedule {
                if op >= 0 {
                    let v: Vec<F> = (0..op).map(|_| F::rand(&mut rng)).collect();
                    let vars: Vec<FpVar<F>> = v
                        .iter()
                        .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
                        .collect();
                    native.absorb(&v);
                    var.absorb(&vars).unwrap();
                } else if op > -100 {
                    let n = (-op) as usize;
                    let expected: Vec<F> = native.squeeze_field_elements(n);
                    let got = var.squeeze_field_elements(n).unwrap();
                    let got: Vec<F> = got.iter().map(|g| g.value().unwrap()).collect();
                    assert_eq!(got, expected);
                } else {
                    let n = (-op) as usize;
                    let expected = native.squeeze_bits(n);
                    let got: Vec<bool> = var
                        .squeeze_bits(n)
                        .unwrap()
                        .iter()
                        .map(|b| b.value().unwrap())
                        .collect();
                    assert_eq!(got, expected);
                }
            }
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn is_much_sparser_than_the_arkworks_gadget() {
        let params = poseidon_config::<F>();
        let run = |light: bool| {
            let cs = ConstraintSystem::<F>::new_ref();
            cs.set_mode(SynthesisMode::Prove {
                construct_matrices: true,
            });
            let v: Vec<FpVar<F>> = (0..8)
                .map(|i| FpVar::new_witness(cs.clone(), || Ok(F::from(i as u64))).unwrap())
                .collect();
            if light {
                let mut s = PoseidonVar::new(cs.clone(), &params);
                s.absorb(&v).unwrap();
                s.squeeze_field_elements(1).unwrap();
            } else {
                let mut s = PoseidonSpongeVar::new(cs.clone(), &params);
                s.absorb(&v).unwrap();
                s.squeeze_field_elements(1).unwrap();
            }
            weight(&cs)
        };
        let (c_old, nnz_old) = run(false);
        let (c_new, nnz_new) = run(true);
        std::println!(
            "Poseidon, 2 permutations: arkworks {c_old} constraints / {nnz_old} non-zero; \
             low-weight {c_new} / {nnz_new}"
        );
        // Measured: 2.6× fewer non-zero entries for 13% more constraints.
        assert!(nnz_new * 5 < nnz_old * 2);
        assert!(c_new * 5 < c_old * 6);
    }
}
