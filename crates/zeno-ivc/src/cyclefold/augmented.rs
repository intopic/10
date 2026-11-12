//! Step 2: the primary augmented circuit with CycleFold.
//!
//! It runs in `Fr = G1::ScalarField = G2::BaseField`, so the primary
//! instances' scalars `(u, x)` are native and are folded directly, and the
//! secondary (Grumpkin) points are native too. The only foreign objects are
//! the primary commitments (points of `G1`, coordinates in `Fq`): the circuit
//! never computes on them, it only hashes them and forwards them, together
//! with the claimed folds `W' = W + r·W_new` and `E' = E + r·T`, as the public
//! input of two CycleFold instances. Those are folded into the CycleFold
//! accumulator (row commitments on `G2`), whose final satisfiability is what
//! makes the claimed `W'`, `E'` binding.
//!
//! Per step:
//!
//! 1. base case `i = 0`: both accumulators are the default ones, `z_i = z_0`;
//! 2. otherwise the incoming instance attests the previous state:
//!    `u.x = H(vk, i, z_0, z_i, U, U_cf)`;
//! 3. one transcript yields `r` (primary fold), then `r_1`, `r_2` (the two
//!    CycleFold folds);
//! 4. `U' = (W', E', U.u + r, U.x + r·u.x)` and
//!    `U_cf' = U_cf + r_1·cf_1 + r_2·cf_2` (row by row on `G2`, scalars
//!    non-natively modulo `|G2|`);
//! 5. `z_{i+1} = F(z_i)` and the single public input
//!    `x = H(vk, i + 1, z_0, z_{i+1}, U', U_cf')`.

use super::{
    circuit::{CycleFoldCircuit, CF_IO_LEN},
    hyrax::{CfInstance, CfRelaxedInstance},
};
use crate::{nonnative::mul_add_mod, nova_ivc_circuit::StepCircuit};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig,
};
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
use llull_folder::transcript::{point_to_coords, scalar_to_limbs, CHALLENGE_BITS, LIMB_BITS};

/// Domain separator of the CycleFold IVC state hash.
pub const DOMAIN_CF_STATE: u64 = 16;
/// Domain separator of the per-step folding transcript.
pub const DOMAIN_CF_STEP: u64 = 17;

/// The data of one CycleFold fold that the circuit takes as advice: the row
/// commitments of the instance's witness and of the cross term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfFoldAdvice<C: ark_ec::CurveGroup> {
    pub comm_w: Vec<C>,
    pub comm_t: Vec<C>,
}

impl<C: ark_ec::CurveGroup> CfFoldAdvice<C> {
    /// All-identity advice, for the base case (and shape extraction).
    pub fn placeholder(rows_w: usize, rows_e: usize) -> Self {
        Self {
            comm_w: alloc::vec![C::zero(); rows_w],
            comm_t: alloc::vec![C::zero(); rows_e],
        }
    }
}

// ---------------------------------------------------------------------------
// Native transcript, mirrored exactly by the circuit below.
// ---------------------------------------------------------------------------

/// A primary commitment as `Fr` elements: both coordinates, two limbs each.
pub fn g1_limbs<G1: SWCurveConfig, F: PrimeField>(p: &Projective<G1>) -> Vec<F>
where
    G1::BaseField: PrimeField,
{
    point_to_coords(p)
        .iter()
        .flat_map(scalar_to_limbs::<G1::BaseField, F>)
        .collect()
}

/// `comm_W, comm_E, u, x` of the primary accumulator.
pub fn absorb_primary<G1: SWCurveConfig>(
    out: &mut Vec<G1::ScalarField>,
    u: &RelaxedR1CSInstance<Projective<G1>>,
) where
    G1::BaseField: PrimeField,
{
    out.extend(g1_limbs::<G1, G1::ScalarField>(&u.comm_w));
    out.extend(g1_limbs::<G1, G1::ScalarField>(&u.comm_e));
    out.push(u.u);
    out.extend_from_slice(&u.x);
}

/// `comm_W, x` of a fresh primary instance.
pub fn absorb_fresh<G1: SWCurveConfig>(
    out: &mut Vec<G1::ScalarField>,
    u: &R1CSInstance<Projective<G1>>,
) where
    G1::BaseField: PrimeField,
{
    out.extend(g1_limbs::<G1, G1::ScalarField>(&u.comm_w));
    out.extend_from_slice(&u.x);
}

/// Native coordinates of secondary points.
pub fn absorb_rows<G2: SWCurveConfig>(out: &mut Vec<G2::BaseField>, rows: &[Projective<G2>])
where
    G2::BaseField: PrimeField,
{
    for p in rows {
        out.extend(point_to_coords(p));
    }
}

/// `comm_W rows, comm_E rows, u, x` of the CycleFold accumulator.
pub fn absorb_cf_acc<G2: SWCurveConfig>(
    out: &mut Vec<G2::BaseField>,
    u: &CfRelaxedInstance<Projective<G2>>,
) where
    G2::BaseField: PrimeField,
{
    absorb_rows(out, &u.comm_w);
    absorb_rows(out, &u.comm_e);
    out.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(&u.u));
    for xi in &u.x {
        out.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(xi));
    }
}

/// `comm_W rows, x` of a fresh CycleFold instance.
pub fn absorb_cf_fresh<G2: SWCurveConfig>(
    out: &mut Vec<G2::BaseField>,
    u: &CfInstance<Projective<G2>>,
) where
    G2::BaseField: PrimeField,
{
    absorb_rows(out, &u.comm_w);
    for xi in &u.x {
        out.extend(scalar_to_limbs::<G2::ScalarField, G2::BaseField>(xi));
    }
}

/// The IVC state hash `H(vk, i, z_0, z_i, U, U_cf)`, one field element.
pub fn state_hash<G1, G2>(
    config: &PoseidonConfig<G1::ScalarField>,
    digest: G1::ScalarField,
    i: u64,
    z0: &[G1::ScalarField],
    zi: &[G1::ScalarField],
    acc: &RelaxedR1CSInstance<Projective<G1>>,
    cf_acc: &CfRelaxedInstance<Projective<G2>>,
) -> G1::ScalarField
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
{
    let mut input = alloc::vec![
        G1::ScalarField::from(DOMAIN_CF_STATE),
        digest,
        G1::ScalarField::from(i)
    ];
    input.extend_from_slice(z0);
    input.extend_from_slice(zi);
    absorb_primary(&mut input, acc);
    absorb_cf_acc(&mut input, cf_acc);
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&input);
    sponge.squeeze_field_elements(1)[0]
}

/// The prefix of the step transcript, up to the primary challenge `r`.
pub fn primary_challenge_input<G1: SWCurveConfig>(
    digest: G1::ScalarField,
    acc: &RelaxedR1CSInstance<Projective<G1>>,
    fresh: &R1CSInstance<Projective<G1>>,
    comm_t: &Projective<G1>,
) -> Vec<G1::ScalarField>
where
    G1::BaseField: PrimeField,
{
    let mut input = alloc::vec![G1::ScalarField::from(DOMAIN_CF_STEP), digest];
    absorb_primary(&mut input, acc);
    absorb_fresh(&mut input, fresh);
    input.extend(g1_limbs::<G1, G1::ScalarField>(comm_t));
    input
}

/// Squeezes a `CHALLENGE_BITS`-bit challenge from a native sponge.
pub fn squeeze_challenge<F: PrimeField + Absorb>(sponge: &mut PoseidonSponge<F>) -> Vec<bool> {
    sponge.squeeze_bits(CHALLENGE_BITS)
}

// ---------------------------------------------------------------------------
// The circuit.
// ---------------------------------------------------------------------------

type NativePoint<G2> = ProjectiveVar<G2, FpVar<<G2 as CurveConfig>::BaseField>>;

/// A foreign field element (a coordinate of `G1`, or a scalar of `G2`) as
/// little-endian bits in the native field.
fn foreign_bits<F: PrimeField, S: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    v: &S,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    v.into_bigint().to_bits_le()[..S::MODULUS_BIT_SIZE as usize]
        .iter()
        .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
        .collect()
}

/// `count` little-endian `LIMB_BITS`-bit limbs, zero-padded; matches
/// [`scalar_to_limbs`] for `count = ⌈bits(S) / LIMB_BITS⌉`.
fn limbs<F: PrimeField>(
    bits: &[Boolean<F>],
    count: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut out: Vec<FpVar<F>> = bits
        .chunks(LIMB_BITS)
        .map(Boolean::le_bits_to_fp)
        .collect::<Result<_, _>>()?;
    assert!(out.len() <= count, "too many limbs");
    out.resize(count, FpVar::zero());
    Ok(out)
}

fn foreign_limbs<F: PrimeField, S: PrimeField>(
    bits: &[Boolean<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    limbs(bits, (S::MODULUS_BIT_SIZE as usize).div_ceil(LIMB_BITS))
}

/// A point of `G1` with foreign coordinates, `(0, 0)` for the identity.
struct ForeignPoint<F: PrimeField> {
    x: Vec<Boolean<F>>,
    y: Vec<Boolean<F>>,
}

impl<F: PrimeField> ForeignPoint<F> {
    fn new<G1: SWCurveConfig>(
        cs: &ConstraintSystemRef<F>,
        p: &Projective<G1>,
    ) -> Result<Self, SynthesisError>
    where
        G1::BaseField: PrimeField,
    {
        let [x, y] = point_to_coords(p);
        Ok(Self {
            x: foreign_bits(cs, &x)?,
            y: foreign_bits(cs, &y)?,
        })
    }

    fn limbs<S: PrimeField>(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut out = foreign_limbs::<F, S>(&self.x)?;
        out.extend(foreign_limbs::<F, S>(&self.y)?);
        Ok(out)
    }
}

fn coords<G2: SWCurveConfig>(
    p: &NativePoint<G2>,
) -> Result<[FpVar<G2::BaseField>; 2], SynthesisError>
where
    G2::BaseField: PrimeField,
{
    let affine = p.to_affine()?;
    Ok([affine.x, affine.y])
}

fn rows_coords<G2: SWCurveConfig>(
    rows: &[NativePoint<G2>],
) -> Result<Vec<FpVar<G2::BaseField>>, SynthesisError>
where
    G2::BaseField: PrimeField,
{
    let mut out = Vec::with_capacity(2 * rows.len());
    for p in rows {
        out.extend(coords::<G2>(p)?);
    }
    Ok(out)
}

fn alloc_rows<G2: SWCurveConfig>(
    cs: &ConstraintSystemRef<G2::BaseField>,
    rows: &[Projective<G2>],
) -> Result<Vec<NativePoint<G2>>, SynthesisError>
where
    G2::BaseField: PrimeField,
{
    rows.iter()
        .map(|p| NativePoint::<G2>::new_witness(cs.clone(), || Ok(*p)))
        .collect()
}

/// The CycleFold accumulator inside the circuit.
struct CfAccVar<G2: SWCurveConfig>
where
    G2::BaseField: PrimeField,
{
    comm_w: Vec<NativePoint<G2>>,
    comm_e: Vec<NativePoint<G2>>,
    u: Vec<Boolean<G2::BaseField>>,
    x: Vec<Vec<Boolean<G2::BaseField>>>,
}

impl<G2: SWCurveConfig> CfAccVar<G2>
where
    G2::BaseField: PrimeField,
{
    /// The same field elements as [`absorb_cf_acc`].
    fn elems(&self) -> Result<Vec<FpVar<G2::BaseField>>, SynthesisError> {
        let mut out = rows_coords::<G2>(&self.comm_w)?;
        out.extend(rows_coords::<G2>(&self.comm_e)?);
        out.extend(foreign_limbs::<_, G2::ScalarField>(&self.u)?);
        for xi in &self.x {
            out.extend(foreign_limbs::<_, G2::ScalarField>(xi)?);
        }
        Ok(out)
    }
}

/// One invocation of the primary augmented circuit, with all its inputs.
pub struct CfAugmentedCircuit<'a, G1, G2, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
{
    pub poseidon: &'a PoseidonConfig<G1::ScalarField>,
    pub step: &'a SC,
    pub digest: G1::ScalarField,
    pub i: u64,
    pub z0: Vec<G1::ScalarField>,
    pub zi: Vec<G1::ScalarField>,
    /// Running primary accumulator `U` (one public input).
    pub acc: RelaxedR1CSInstance<Projective<G1>>,
    /// The previous step's instance `u`, folded into `U` here.
    pub fresh: R1CSInstance<Projective<G1>>,
    pub comm_t: Projective<G1>,
    /// Running CycleFold accumulator `U_cf`.
    pub cf_acc: CfRelaxedInstance<Projective<G2>>,
    /// The CycleFold instances for `W'` and for `E'`, in this order.
    pub cf: [CfFoldAdvice<Projective<G2>>; 2],
}

impl<G1, G2, SC> CfAugmentedCircuit<'_, G1, G2, SC>
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
    SC: StepCircuit<G1::ScalarField>,
{
    /// The CycleFold statements this step delegates, given the primary
    /// challenge `r`: `W' = W + r·W_new` and `E' = E + r·T`.
    pub fn delegated(&self, r_bits: &[bool]) -> [CycleFoldCircuit<G1>; 2] {
        [
            CycleFoldCircuit::new(r_bits.to_vec(), self.acc.comm_w, self.fresh.comm_w),
            CycleFoldCircuit::new(r_bits.to_vec(), self.acc.comm_e, self.comm_t),
        ]
    }

    /// Generates the constraints and returns the values of `z_{i+1}`.
    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<G1::ScalarField>, SynthesisError> {
        type Fp<G2> = FpVar<<G2 as CurveConfig>::BaseField>;
        let arity = self.step.arity();
        assert_eq!(self.z0.len(), arity);
        assert_eq!(self.zi.len(), arity);
        assert_eq!(self.acc.x.len(), 1);
        assert_eq!(self.fresh.x.len(), 1);
        assert_eq!(self.cf_acc.x.len(), CF_IO_LEN);
        for advice in &self.cf {
            assert_eq!(advice.comm_w.len(), self.cf_acc.comm_w.len());
            assert_eq!(advice.comm_t.len(), self.cf_acc.comm_e.len());
        }

        // ---- Private inputs -------------------------------------------------
        let digest = Fp::<G2>::new_witness(cs.clone(), || Ok(self.digest))?;
        let i = Fp::<G2>::new_witness(cs.clone(), || Ok(G1::ScalarField::from(self.i)))?;
        let z0 = Vec::<Fp<G2>>::new_witness(cs.clone(), || Ok(self.z0.clone()))?;
        let zi = Vec::<Fp<G2>>::new_witness(cs.clone(), || Ok(self.zi.clone()))?;

        let acc_w = ForeignPoint::new(&cs, &self.acc.comm_w)?;
        let acc_e = ForeignPoint::new(&cs, &self.acc.comm_e)?;
        let acc_u = Fp::<G2>::new_witness(cs.clone(), || Ok(self.acc.u))?;
        let acc_x = Fp::<G2>::new_witness(cs.clone(), || Ok(self.acc.x[0]))?;
        let fresh_w = ForeignPoint::new(&cs, &self.fresh.comm_w)?;
        let fresh_x = Fp::<G2>::new_witness(cs.clone(), || Ok(self.fresh.x[0]))?;
        let comm_t = ForeignPoint::new(&cs, &self.comm_t)?;

        let cf_acc = CfAccVar::<G2> {
            comm_w: alloc_rows(&cs, &self.cf_acc.comm_w)?,
            comm_e: alloc_rows(&cs, &self.cf_acc.comm_e)?,
            u: foreign_bits(&cs, &self.cf_acc.u)?,
            x: self
                .cf_acc
                .x
                .iter()
                .map(|xi| foreign_bits(&cs, xi))
                .collect::<Result<_, _>>()?,
        };
        let cf_new = self
            .cf
            .iter()
            .map(|a| Ok((alloc_rows(&cs, &a.comm_w)?, alloc_rows(&cs, &a.comm_t)?)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let primary_elems = |w: &ForeignPoint<_>,
                             e: &ForeignPoint<_>,
                             u: &Fp<G2>,
                             x: &Fp<G2>|
         -> Result<Vec<Fp<G2>>, SynthesisError> {
            let mut out = w.limbs::<G1::BaseField>()?;
            out.extend(e.limbs::<G1::BaseField>()?);
            out.push(u.clone());
            out.push(x.clone());
            Ok(out)
        };
        let acc_elems = primary_elems(&acc_w, &acc_e, &acc_u, &acc_x)?;
        let cf_elems = cf_acc.elems()?;

        // ---- Base case: default accumulators, z_i = z_0 ---------------------
        let is_base = i.is_zero()?;
        let zero = Fp::<G2>::zero();
        for elem in acc_elems.iter().chain(&cf_elems) {
            elem.conditional_enforce_equal(&zero, &is_base)?;
        }
        for (a, b) in zi.iter().zip(&z0) {
            a.conditional_enforce_equal(b, &is_base)?;
        }

        // ---- Recursive case: u.x = H(vk, i, z_0, z_i, U, U_cf) --------------
        let hash = |i: &Fp<G2>,
                    z: &[Fp<G2>],
                    acc: &[Fp<G2>],
                    cf: &[Fp<G2>]|
         -> Result<Fp<G2>, SynthesisError> {
            let mut input = alloc::vec![
                Fp::<G2>::constant(G1::ScalarField::from(DOMAIN_CF_STATE)),
                digest.clone(),
                i.clone(),
            ];
            input.extend_from_slice(&z0);
            input.extend_from_slice(z);
            input.extend_from_slice(acc);
            input.extend_from_slice(cf);
            let mut sponge = PoseidonSpongeVar::new(cs.clone(), self.poseidon);
            sponge.absorb(&input)?;
            Ok(sponge.squeeze_field_elements(1)?.remove(0))
        };
        hash(&i, &zi, &acc_elems, &cf_elems)?.conditional_enforce_equal(&fresh_x, &!&is_base)?;

        // ---- Primary fold: r, then u and x natively ---------------------------
        let mut transcript = PoseidonSpongeVar::new(cs.clone(), self.poseidon);
        let mut input = alloc::vec![
            Fp::<G2>::constant(G1::ScalarField::from(DOMAIN_CF_STEP)),
            digest.clone()
        ];
        input.extend_from_slice(&acc_elems);
        input.extend(fresh_w.limbs::<G1::BaseField>()?);
        input.push(fresh_x.clone());
        input.extend(comm_t.limbs::<G1::BaseField>()?);
        transcript.absorb(&input)?;
        let r = transcript.squeeze_bits(CHALLENGE_BITS)?;
        let r_native = Boolean::le_bits_to_fp(&r)?;
        let folded_u = &acc_u + &r_native;
        let folded_x = &acc_x + &r_native * &fresh_x;

        // The folded commitments are advice: only the CycleFold instances
        // below, once their accumulator is decided, pin them down.
        let r_value: Result<Vec<bool>, _> = r.iter().map(|b| b.value()).collect();
        let delegated =
            self.delegated(&r_value.unwrap_or_else(|_| alloc::vec![false; CHALLENGE_BITS]));
        let folded_w = ForeignPoint::new(&cs, &delegated[0].output())?;
        let folded_e = ForeignPoint::new(&cs, &delegated[1].output())?;

        // Public inputs of the two CycleFold instances: (r, p1, p2, out).
        let cf_io = |p1: &ForeignPoint<_>, p2: &ForeignPoint<_>, out: &ForeignPoint<_>| {
            alloc::vec![
                r.clone(),
                p1.x.clone(),
                p1.y.clone(),
                p2.x.clone(),
                p2.y.clone(),
                out.x.clone(),
                out.y.clone(),
            ]
        };
        let cf_inputs = [
            cf_io(&acc_w, &fresh_w, &folded_w),
            cf_io(&acc_e, &comm_t, &folded_e),
        ];

        // ---- CycleFold folds: U_cf ← U_cf + r_k·cf_k -------------------------
        transcript.absorb(&cf_elems)?;
        let mut acc = cf_acc;
        for ((w_rows, t_rows), io) in cf_new.iter().zip(&cf_inputs) {
            let mut input = rows_coords::<G2>(w_rows)?;
            for xi in io {
                input.extend(foreign_limbs::<_, G2::ScalarField>(xi)?);
            }
            input.extend(rows_coords::<G2>(t_rows)?);
            transcript.absorb(&input)?;
            let r_k = transcript.squeeze_bits(CHALLENGE_BITS)?;

            for (a, b) in acc.comm_w.iter_mut().zip(w_rows) {
                *a = &*a + b.scalar_mul_le(r_k.iter())?;
            }
            for (a, t) in acc.comm_e.iter_mut().zip(t_rows) {
                *a = &*a + t.scalar_mul_le(r_k.iter())?;
            }
            acc.u = mul_add_mod::<_, G2::ScalarField>(&cs, &acc.u, &r_k, &[Boolean::TRUE])?;
            for (a, xi) in acc.x.iter_mut().zip(io) {
                *a = mul_add_mod::<_, G2::ScalarField>(&cs, a, &r_k, xi)?;
            }
        }

        // ---- New accumulators (unchanged defaults in the base case) ----------
        let folded_elems = primary_elems(&folded_w, &folded_e, &folded_u, &folded_x)?;
        let folded_cf_elems = acc.elems()?;
        let keep_default = |elems: Vec<Fp<G2>>| -> Result<Vec<Fp<G2>>, SynthesisError> {
            elems.iter().map(|e| is_base.select(&zero, e)).collect()
        };
        let new_acc = keep_default(folded_elems)?;
        let new_cf = keep_default(folded_cf_elems)?;

        // ---- Application step and the single public input --------------------
        let z_next = self.step.synthesize(cs.clone(), &zi)?;
        assert_eq!(z_next.len(), arity);
        let i_next = &i + Fp::<G2>::one();
        let out = hash(&i_next, &z_next, &new_acc, &new_cf)?;
        let x = Fp::<G2>::new_input(cs.clone(), || out.value())?;
        x.enforce_equal(&out)?;

        z_next.iter().map(|z| z.value()).collect()
    }
}

/// The primary challenge `r` as bits, from the native transcript prefix.
pub fn primary_challenge<G1: SWCurveConfig>(
    sponge: &mut PoseidonSponge<G1::ScalarField>,
    digest: G1::ScalarField,
    acc: &RelaxedR1CSInstance<Projective<G1>>,
    fresh: &R1CSInstance<Projective<G1>>,
    comm_t: &Projective<G1>,
) -> Vec<bool>
where
    G1::BaseField: PrimeField,
    G1::ScalarField: Absorb,
{
    sponge.absorb(&primary_challenge_input::<G1>(digest, acc, fresh, comm_t));
    squeeze_challenge(sponge)
}
