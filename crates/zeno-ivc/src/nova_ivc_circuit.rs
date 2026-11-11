//! The augmented step circuit `F'` (spec §2.6).
//!
//! Running in the field `F = P::BaseField`, it folds instances committed on
//! the curve `P` (whose point coordinates are native here) and:
//!
//! 1. computes `z_{i+1} = F(z_i)`;
//! 2. checks that the incoming instance `u` attests the previous state, i.e.
//!    `u.x[0] = H(vk, i, z_0, z_i, U)`, then folds `U' = NIFS.Verify(U, u, T)`
//!    with two scalar multiplications;
//! 3. exposes `x = (u.x[1], H(vk, i + 1, z_0, z_{i+1}, U'))`.

use crate::nonnative::{mul_add_mod, pack_bits};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
    Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core_r1cs::{R1CSInstance, RelaxedR1CSInstance};
use llull_folder::transcript::{CHALLENGE_BITS, DOMAIN_FOLD, DOMAIN_STATE, HASH_BITS, LIMB_BITS};

/// The application step function `z_{i+1} = F(z_i; ω_i)`.
///
/// Per-step private inputs `ω_i` live inside the implementing value; the
/// constraint structure must not depend on them.
pub trait StepCircuit<F: PrimeField> {
    /// Number of field elements in the state `z`.
    fn arity(&self) -> usize;

    /// Constrains and returns `z_{i+1}` given `z_i`.
    fn synthesize(
        &self,
        cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

type PointVar<P> = ProjectiveVar<P, FpVar<<P as ark_ec::CurveConfig>::BaseField>>;

/// One invocation of the augmented circuit, with all its (private) inputs.
pub struct AugmentedCircuit<'a, P: SWCurveConfig, SC>
where
    P::BaseField: PrimeField,
{
    pub poseidon: &'a PoseidonConfig<P::BaseField>,
    /// Whether step 0 folds the incoming instance into the default
    /// accumulator (secondary circuit) or ignores it (primary circuit, whose
    /// first incoming instance is a placeholder).
    pub fold_in_base_case: bool,
    pub step: &'a SC,
    pub digest: P::BaseField,
    pub i: u64,
    pub z0: Vec<P::BaseField>,
    pub zi: Vec<P::BaseField>,
    pub acc: RelaxedR1CSInstance<Projective<P>>,
    pub fresh: R1CSInstance<Projective<P>>,
    pub comm_t: Projective<P>,
}

fn scalar_bits<F: PrimeField, S: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    value: &S,
    n: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    value.into_bigint().to_bits_le()[..n]
        .iter()
        .map(|bit| Boolean::new_witness(cs.clone(), || Ok(*bit)))
        .collect()
}

/// Little-endian `LIMB_BITS`-bit limbs, matching `transcript::scalar_to_limbs`.
fn limbs<F: PrimeField>(bits: &[Boolean<F>]) -> Result<Vec<FpVar<F>>, SynthesisError> {
    bits.chunks(LIMB_BITS).map(Boolean::le_bits_to_fp).collect()
}

/// Affine coordinates, with the identity encoded as `(0, 0)`.
fn coords<P: SWCurveConfig>(p: &PointVar<P>) -> Result<[FpVar<P::BaseField>; 2], SynthesisError>
where
    P::BaseField: PrimeField,
{
    let affine = p.to_affine()?;
    Ok([affine.x, affine.y])
}

fn hash_bits<F: PrimeField + Absorb>(
    cs: &ConstraintSystemRef<F>,
    config: &PoseidonConfig<F>,
    input: &Vec<FpVar<F>>,
    num_bits: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), config);
    sponge.absorb(input)?;
    sponge.squeeze_bits(num_bits)
}

impl<P: SWCurveConfig, SC: StepCircuit<P::BaseField>> AugmentedCircuit<'_, P, SC>
where
    P::BaseField: PrimeField + Absorb,
{
    /// Generates the constraints and returns the values of `z_{i+1}`.
    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<P::BaseField>,
    ) -> Result<Vec<P::BaseField>, SynthesisError> {
        type Fp<P> = FpVar<<P as ark_ec::CurveConfig>::BaseField>;
        let s_bits = P::ScalarField::MODULUS_BIT_SIZE as usize;
        assert_eq!(self.z0.len(), self.step.arity());
        assert_eq!(self.zi.len(), self.step.arity());
        assert_eq!(self.acc.x.len(), 2);
        assert_eq!(self.fresh.x.len(), 2);

        // ---- Private inputs -------------------------------------------------
        let digest = Fp::<P>::new_witness(cs.clone(), || Ok(self.digest))?;
        let i = Fp::<P>::new_witness(cs.clone(), || Ok(P::BaseField::from(self.i)))?;
        let z0 = Vec::<Fp<P>>::new_witness(cs.clone(), || Ok(self.z0.clone()))?;
        let zi = Vec::<Fp<P>>::new_witness(cs.clone(), || Ok(self.zi.clone()))?;

        let acc_e = PointVar::<P>::new_witness(cs.clone(), || Ok(self.acc.comm_e))?;
        let acc_w = PointVar::<P>::new_witness(cs.clone(), || Ok(self.acc.comm_w))?;
        let acc_u = scalar_bits(&cs, &self.acc.u, s_bits)?;
        let acc_x0 = scalar_bits(&cs, &self.acc.x[0], s_bits)?;
        let acc_x1 = scalar_bits(&cs, &self.acc.x[1], s_bits)?;

        let fresh_w = PointVar::<P>::new_witness(cs.clone(), || Ok(self.fresh.comm_w))?;
        let fresh_x0 = scalar_bits(&cs, &self.fresh.x[0], HASH_BITS)?;
        let fresh_x1 = scalar_bits(&cs, &self.fresh.x[1], HASH_BITS)?;
        let comm_t = PointVar::<P>::new_witness(cs.clone(), || Ok(self.comm_t))?;

        // The accumulator as the sponge sees it: comm_E, u, comm_W, x.
        let mut acc_elems: Vec<Fp<P>> = Vec::with_capacity(10);
        acc_elems.extend(coords::<P>(&acc_e)?);
        acc_elems.extend(limbs(&acc_u)?);
        acc_elems.extend(coords::<P>(&acc_w)?);
        acc_elems.extend(limbs(&acc_x0)?);
        acc_elems.extend(limbs(&acc_x1)?);
        let fresh_elems: Vec<Fp<P>> = coords::<P>(&fresh_w)?
            .into_iter()
            .chain(limbs(&fresh_x0)?)
            .chain(limbs(&fresh_x1)?)
            .collect();

        // ---- Base case: the accumulator is the default one, z_i = z_0 -------
        let is_base = i.is_zero()?;
        let zero = Fp::<P>::zero();
        for elem in &acc_elems {
            elem.conditional_enforce_equal(&zero, &is_base)?;
        }
        for (a, b) in zi.iter().zip(&z0) {
            a.conditional_enforce_equal(b, &is_base)?;
        }

        // ---- Recursive case: u.x[0] = H(vk, i, z_0, z_i, U) ------------------
        let state_input = |i: &Fp<P>, z: &[Fp<P>], acc: &[Fp<P>]| -> Vec<Fp<P>> {
            let mut input = alloc::vec![
                Fp::<P>::constant(P::BaseField::from(DOMAIN_STATE)),
                digest.clone(),
                i.clone(),
            ];
            input.extend_from_slice(&z0);
            input.extend_from_slice(z);
            input.extend_from_slice(acc);
            input
        };
        let hash_in = hash_bits(
            &cs,
            self.poseidon,
            &state_input(&i, &zi, &acc_elems),
            HASH_BITS,
        )?;
        pack_bits(&hash_in)?.conditional_enforce_equal(&pack_bits(&fresh_x0)?, &!&is_base)?;

        // ---- Fold: U' = NIFS.Verify(U, u, T) ---------------------------------
        let mut challenge_input = alloc::vec![
            Fp::<P>::constant(P::BaseField::from(DOMAIN_FOLD)),
            digest.clone()
        ];
        challenge_input.extend_from_slice(&acc_elems);
        challenge_input.extend_from_slice(&fresh_elems);
        challenge_input.extend(coords::<P>(&comm_t)?);
        let r = hash_bits(&cs, self.poseidon, &challenge_input, CHALLENGE_BITS)?;

        // Exactly two scalar multiplications: r·comm_T and r·comm_W.
        let folded_e = acc_e + comm_t.scalar_mul_le(r.iter())?;
        let folded_w = acc_w + fresh_w.scalar_mul_le(r.iter())?;
        let one = [Boolean::TRUE];
        let folded_u = mul_add_mod::<_, P::ScalarField>(&cs, &acc_u, &r, &one)?;
        let folded_x0 = mul_add_mod::<_, P::ScalarField>(&cs, &acc_x0, &r, &fresh_x0)?;
        let folded_x1 = mul_add_mod::<_, P::ScalarField>(&cs, &acc_x1, &r, &fresh_x1)?;

        let mut folded_elems: Vec<Fp<P>> = Vec::with_capacity(10);
        folded_elems.extend(coords::<P>(&folded_e)?);
        folded_elems.extend(limbs(&folded_u)?);
        folded_elems.extend(coords::<P>(&folded_w)?);
        folded_elems.extend(limbs(&folded_x0)?);
        folded_elems.extend(limbs(&folded_x1)?);

        let new_elems = if self.fold_in_base_case {
            folded_elems
        } else {
            // In the base case the accumulator stays the default (all-zero) one.
            acc_elems
                .iter()
                .zip(&folded_elems)
                .map(|(old, new)| is_base.select(old, new))
                .collect::<Result<Vec<_>, _>>()?
        };

        // ---- Application step and output hash --------------------------------
        let z_next = self.step.synthesize(cs.clone(), &zi)?;
        assert_eq!(z_next.len(), self.step.arity());
        let i_next = &i + Fp::<P>::one();
        let hash_out = hash_bits(
            &cs,
            self.poseidon,
            &state_input(&i_next, &z_next, &new_elems),
            HASH_BITS,
        )?;

        // ---- Public inputs: x = (u.x[1], H(vk, i+1, z_0, z_{i+1}, U')) --------
        let pass_through = pack_bits(&fresh_x1)?;
        let hash_out = pack_bits(&hash_out)?;
        let x0 = Fp::<P>::new_input(cs.clone(), || pass_through.value())?;
        let x1 = Fp::<P>::new_input(cs.clone(), || hash_out.value())?;
        x0.enforce_equal(&pass_through)?;
        x1.enforce_equal(&hash_out)?;

        z_next.iter().map(|z| z.value()).collect()
    }
}
