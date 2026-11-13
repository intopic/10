//! Step 3: the closing circuit of the EVM decider (over BN254's `Fr`).
//!
//! The EVM cannot do Grumpkin arithmetic, so the CycleFold accumulator is
//! decided in two halves:
//!
//! * a Spartan-style sum-check over `Fq` (native for the EVM's `mulmod`)
//!   reduces its relaxed R1CS relation to two multilinear evaluations
//!   `W̃(r_W)` and `Ẽ(r_E)`, and its Hyrax openings to one combined row
//!   `c = γ·w' + e'` (one scalar per column generator) whose inner products
//!   the verifier checks itself;
//! * this circuit checks the remaining group equation over Grumpkin, whose
//!   coordinates are native here:
//!
//! ```text
//! Σ_i s_i·C_i = Σ_j c_j·G_j      (C_i the row commitments, G_j the generators)
//! ```
//!
//! with the row weights `s = (γ·L_W, L_E)`, and recomputes the IVC state hash
//! `h = H(vk, i, z_0, z_i, U, U_cf)` from its public inputs, which ties the
//! rows to the last primary instance (whose public input is `h`).
//!
//! **Public input**, in this order (all in `Fr`): `h`, `i`, `z_0`, `z_i`, the
//! primary accumulator as hashed (`comm_W`, `comm_E` as two limbs per
//! coordinate, `u`, `x`), the CycleFold accumulator as hashed (row
//! coordinates, then `u` and `x` as two limbs each), then for every row the
//! two limbs of the `t` with `2^255 + 2t + 1 ≡ s_i (mod |G2|)` (computed by
//! the verifier), then the two limbs of every `c_j`.

use super::{
    augmented::{absorb_cf_acc, absorb_primary, state_hash, DOMAIN_CF_STATE},
    hyrax::CfRelaxedInstance,
};
use crate::gadgets::{
    ec::{add, fixed_base_msm, odd_t, scalar_mul_odd, AffineVar},
    poseidon::PoseidonVar,
};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core_r1cs::RelaxedR1CSInstance;
use llull_folder::transcript::{point_to_coords, scalar_to_limbs, LIMB_BITS};

/// The closing statement and its witness (everything is public here).
pub struct ClosingCircuit<'a, G1, G2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
{
    pub poseidon: &'a PoseidonConfig<G1::ScalarField>,
    /// `vk` of the IVC, a constant of the circuit.
    pub digest: G1::ScalarField,
    /// The column generators `G_j`, constants of the circuit.
    pub gens: &'a [Affine<G2>],
    pub i: u64,
    pub z0: Vec<G1::ScalarField>,
    pub zi: Vec<G1::ScalarField>,
    pub acc: RelaxedR1CSInstance<Projective<G1>>,
    pub cf_acc: CfRelaxedInstance<Projective<G2>>,
    /// `s_i`: weights of the `comm_W` rows, then of the `comm_E` rows.
    pub row_weights: Vec<G2::ScalarField>,
    /// `c_j`: the combined row.
    pub combined: Vec<G2::ScalarField>,
}

/// Allocates the limbs of a foreign scalar as public inputs and returns its
/// `S::MODULUS_BIT_SIZE` bits, each limb pinned to its bits.
fn public_scalar_bits<F: PrimeField, S: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    v: &S,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let n = S::MODULUS_BIT_SIZE as usize;
    let all = v.into_bigint().to_bits_le();
    let limbs = scalar_to_limbs::<S, F>(v);
    let mut bits = Vec::with_capacity(n);
    for (k, limb) in limbs.iter().enumerate() {
        let start = k * LIMB_BITS;
        let end = ((k + 1) * LIMB_BITS).min(n);
        let limb_var = FpVar::new_input(cs.clone(), || Ok(*limb))?;
        let chunk = all[start..end]
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<Vec<_>, _>>()?;
        Boolean::le_bits_to_fp(&chunk)?.enforce_equal(&limb_var)?;
        bits.extend(chunk);
    }
    Ok(bits)
}

impl<G1, G2> ClosingCircuit<'_, G1, G2>
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
{
    fn hash(&self) -> G1::ScalarField {
        state_hash::<G1, G2>(
            self.poseidon,
            self.digest,
            self.i,
            &self.z0,
            &self.zi,
            &self.acc,
            &self.cf_acc,
        )
    }

    /// The public input of an honest statement (with the state hash
    /// recomputed from the state).
    pub fn public_inputs(&self) -> Vec<G1::ScalarField> {
        Self::inputs(
            self.hash(),
            self.i,
            &self.z0,
            &self.zi,
            &self.acc,
            &self.cf_acc,
            &self.row_weights,
            &self.combined,
        )
    }

    /// The public input as a verifier assembles it from a claimed state: `h`
    /// is the public input of the last primary instance, which the circuit
    /// then proves to be the state hash. This is the one definition of the
    /// layout (the contract mirrors it in `_closingInstance`).
    #[allow(clippy::too_many_arguments)]
    pub fn inputs(
        h: G1::ScalarField,
        i: u64,
        z0: &[G1::ScalarField],
        zi: &[G1::ScalarField],
        acc: &RelaxedR1CSInstance<Projective<G1>>,
        cf_acc: &CfRelaxedInstance<Projective<G2>>,
        row_weights: &[G2::ScalarField],
        combined: &[G2::ScalarField],
    ) -> Vec<G1::ScalarField> {
        let mut x = alloc::vec![h, G1::ScalarField::from(i)];
        x.extend_from_slice(z0);
        x.extend_from_slice(zi);
        absorb_primary(&mut x, acc);
        absorb_cf_acc(&mut x, cf_acc);
        for s in row_weights {
            x.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(&odd_t(
                *s,
            )));
        }
        for c in combined {
            x.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(c));
        }
        x
    }

    /// The group equation, natively.
    pub fn holds(&self) -> bool {
        let rows = self.cf_acc.comm_w.iter().chain(&self.cf_acc.comm_e);
        let lhs: Projective<G2> = rows.zip(&self.row_weights).map(|(c, s)| *c * s).sum();
        let rhs: Projective<G2> = self
            .gens
            .iter()
            .zip(&self.combined)
            .map(|(g, c)| *g * c)
            .sum();
        lhs == rhs
    }

    /// Generates the constraints.
    pub fn synthesize(
        &self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<(), SynthesisError> {
        type Fp<G2> = FpVar<<G2 as CurveConfig>::BaseField>;
        let rows = self.cf_acc.comm_w.len() + self.cf_acc.comm_e.len();
        assert_eq!(self.row_weights.len(), rows, "one weight per row");
        assert_eq!(
            self.combined.len(),
            self.gens.len(),
            "one scalar per column"
        );

        // ---- Public inputs: the state ------------------------------------
        let h = Fp::<G2>::new_input(cs.clone(), || Ok(self.hash()))?;
        let i = Fp::<G2>::new_input(cs.clone(), || Ok(G1::ScalarField::from(self.i)))?;
        let z0 = Vec::<Fp<G2>>::new_input(cs.clone(), || Ok(self.z0.clone()))?;
        let zi = Vec::<Fp<G2>>::new_input(cs.clone(), || Ok(self.zi.clone()))?;
        let mut acc_values = Vec::new();
        absorb_primary(&mut acc_values, &self.acc);
        let acc = Vec::<Fp<G2>>::new_input(cs.clone(), || Ok(acc_values))?;

        let row_points = self
            .cf_acc
            .comm_w
            .iter()
            .chain(&self.cf_acc.comm_e)
            .map(|p| AffineVar::new_input::<G2>(&cs, point_to_coords(p)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut scalar_limbs = Vec::new();
        scalar_limbs.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(
            &self.cf_acc.u,
        ));
        for xi in &self.cf_acc.x {
            scalar_limbs.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(xi));
        }
        let cf_scalars = Vec::<Fp<G2>>::new_input(cs.clone(), || Ok(scalar_limbs))?;

        // ---- h = H(vk, i, z_0, z_i, U, U_cf) -------------------------------
        let mut input = alloc::vec![
            Fp::<G2>::constant(G1::ScalarField::from(DOMAIN_CF_STATE)),
            Fp::<G2>::constant(self.digest),
            i,
        ];
        input.extend(z0);
        input.extend(zi);
        input.extend(acc);
        for p in &row_points {
            input.extend(p.coords());
        }
        input.extend(cf_scalars);
        let mut sponge = PoseidonVar::new(cs.clone(), self.poseidon);
        sponge.absorb(&input)?;
        sponge.squeeze_field_elements(1)?[0].enforce_equal(&h)?;

        // ---- Σ_i s_i·C_i ---------------------------------------------------
        let mut lhs = AffineVar::identity();
        for (point, s) in row_points.iter().zip(&self.row_weights) {
            let t = public_scalar_bits(&cs, &odd_t(*s))?;
            let product = scalar_mul_odd::<G2>(&cs, point, &t)?;
            lhs = add::<G2>(&cs, &lhs, &product)?;
        }

        // ---- Σ_j c_j·G_j ---------------------------------------------------
        let scalars = self
            .combined
            .iter()
            .map(|c| public_scalar_bits(&cs, c))
            .collect::<Result<Vec<_>, _>>()?;
        let rhs = fixed_base_msm::<G2>(&cs, self.gens, &scalars)?;

        lhs.x.enforce_equal(&rhs.x)?;
        lhs.y.enforce_equal(&rhs.y)?;
        lhs.inf.enforce_equal(&rhs.inf)?;
        Ok(())
    }
}

/// The closing statement's values for an accumulator, given the evaluation
/// points of `W̃` and `Ẽ` and the batching scalar `γ` (in the EVM decider
/// these come from its transcript): returns `(row_weights, combined,
/// W̃(r_W), Ẽ(r_E))`.
pub fn closing_scalars<S: PrimeField>(
    w: &[S],
    e: &[S],
    cols: usize,
    r_w: &[S],
    r_e: &[S],
    gamma: S,
) -> (Vec<S>, Vec<S>, S, S) {
    use super::hyrax::hyrax_open;
    let (l_w, w_row, w_eval) = hyrax_open(w, cols, r_w);
    let (l_e, e_row, e_eval) = hyrax_open(e, cols, r_e);
    let mut weights: Vec<S> = l_w.iter().map(|l| gamma * l).collect();
    weights.extend(l_e);
    let combined = w_row
        .iter()
        .zip(&e_row)
        .map(|(a, b)| gamma * a + b)
        .collect();
    (weights, combined, w_eval, e_eval)
}
