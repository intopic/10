//! The CycleFold IVC prover/verifier state machine.

use super::{
    augmented::{
        absorb_cf_acc, absorb_cf_fresh, absorb_rows, primary_challenge, squeeze_challenge,
        state_hash, CfAugmentedCircuit, CfFoldAdvice,
    },
    circuit::{CycleFoldCircuit, CF_IO_LEN},
    hyrax::{
        cf_check, cf_commit, cf_cross_term, cf_fold_instance, cf_fold_witness, CfRelaxedInstance,
        CfRelaxedWitness, HyraxKey,
    },
};
use crate::{gadgets::ec::odd_scalar, ivc_stepper::IvcError, nova_ivc_circuit::StepCircuit};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{PrimeField, Zero};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use core_r1cs::{
    ark_bridge::{assignment_from_cs, shape_from_cs},
    R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness,
};
use llull_folder::{
    check_accumulator, commit_witness, nifs_prove_with, transcript::poseidon_config, CommitmentKey,
    FoldError,
};
use sha2::{Digest, Sha256};

fn new_cs<F: PrimeField>(construct_matrices: bool) -> ConstraintSystemRef<F> {
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_mode(SynthesisMode::Prove { construct_matrices });
    cs
}

/// Public parameters of a CycleFold IVC instance for one step function.
pub struct CycleFoldParams<G1: SWCurveConfig, G2: SWCurveConfig>
where
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
{
    /// Shape of the primary augmented circuit (over `G1::ScalarField`).
    pub shape: R1CSShape<G1::ScalarField>,
    /// Commitment key of primary instances (hash-to-curve Pedersen, or the
    /// powers of a KZG reference string for the EVM decider).
    pub ck: CommitmentKey<Projective<G1>>,
    /// Shape of the CycleFold circuit (over `G1::BaseField`).
    pub cf_shape: R1CSShape<G1::BaseField>,
    /// Column generators of the CycleFold row commitments.
    pub cf_key: HyraxKey<Projective<G2>>,
    pub poseidon: PoseidonConfig<G1::ScalarField>,
    /// `vk`: binds both shapes and both keys.
    pub digest: G1::ScalarField,
    pub arity: usize,
}

/// The constant-size IVC state: a proof that `z_i = F^i(z_0)`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize)]
pub struct CycleFoldAccumulator<G1: SWCurveConfig, G2: SWCurveConfig>
where
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField,
{
    pub i: u64,
    pub z0: Vec<G1::ScalarField>,
    pub zi: Vec<G1::ScalarField>,
    /// All primary instances but the last one.
    pub acc: (
        RelaxedR1CSInstance<Projective<G1>>,
        RelaxedR1CSWitness<Projective<G1>>,
    ),
    /// The last primary instance; its public input is the state hash.
    pub last: (R1CSInstance<Projective<G1>>, R1CSWitness<Projective<G1>>),
    /// All CycleFold instances so far.
    pub cf: (
        CfRelaxedInstance<Projective<G2>>,
        CfRelaxedWitness<G2::ScalarField>,
    ),
}

impl<G1, G2> CycleFoldParams<G1, G2>
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
{
    /// Transparent parameters: hash-to-curve generators for both curves.
    /// `cols` is the number of columns (a power of two) of the CycleFold row
    /// commitments.
    pub fn setup<SC: StepCircuit<G1::ScalarField>>(
        step: &SC,
        label: &[u8],
        cols: usize,
    ) -> Result<Self, IvcError> {
        Self::setup_with_key(step, label, cols, |len| {
            CommitmentKey::setup(&[label, b"/primary"].concat(), len)
        })
    }

    /// As [`Self::setup`], with the primary commitment key supplied by the
    /// caller (e.g. the powers of a KZG reference string, so that the final
    /// primary accumulator can be decided by the universal EVM decider).
    pub fn setup_with_key<SC: StepCircuit<G1::ScalarField>>(
        step: &SC,
        label: &[u8],
        cols: usize,
        primary_key: impl FnOnce(usize) -> CommitmentKey<Projective<G1>>,
    ) -> Result<Self, IvcError> {
        let poseidon = poseidon_config::<G1::ScalarField>();
        let arity = step.arity();
        let (shape, cf_shape, cf_key) = Self::shapes(step, label, cols)?;

        let ck = primary_key(
            shape
                .num_vars
                .max(shape.num_constraints)
                .next_power_of_two(),
        );
        assert!(
            ck.len() >= shape.num_vars.max(shape.num_constraints),
            "primary commitment key too short"
        );

        let mut bytes = Vec::new();
        let ser = "serializing to a Vec cannot fail";
        shape.serialize_compressed(&mut bytes).expect(ser);
        cf_shape.serialize_compressed(&mut bytes).expect(ser);
        ck.gens.serialize_compressed(&mut bytes).expect(ser);
        ck.h.serialize_compressed(&mut bytes).expect(ser);
        cf_key.ck.gens.serialize_compressed(&mut bytes).expect(ser);
        let mut hasher = Sha256::new();
        hasher.update(b"zeno-llull/cyclefold-ivc-digest/v1");
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update((arity as u64).to_le_bytes());
        hasher.update((cols as u64).to_le_bytes());
        hasher.update(&bytes);
        let digest = G1::ScalarField::from_le_bytes_mod_order(&hasher.finalize()[..31]);

        Ok(Self {
            shape,
            ck,
            cf_shape,
            cf_key,
            poseidon,
            digest,
            arity,
        })
    }

    /// The two circuit shapes and the CycleFold column generators, without
    /// the (larger) primary commitment key. Useful to measure circuit sizes.
    #[allow(clippy::type_complexity)]
    pub fn shapes<SC: StepCircuit<G1::ScalarField>>(
        step: &SC,
        label: &[u8],
        cols: usize,
    ) -> Result<
        (
            R1CSShape<G1::ScalarField>,
            R1CSShape<G1::BaseField>,
            HyraxKey<Projective<G2>>,
        ),
        IvcError,
    > {
        let poseidon = poseidon_config::<G1::ScalarField>();
        let arity = step.arity();

        let cs = new_cs(true);
        CycleFoldCircuit::<G1>::placeholder().synthesize(cs.clone())?;
        let cf_shape = shape_from_cs(&cs)?;
        let cf_key = HyraxKey::setup(&[label, b"/cyclefold"].concat(), cols);
        let (rows_w, rows_e) = (
            cf_key.rows(cf_shape.num_vars),
            cf_key.rows(cf_shape.num_constraints),
        );

        // The structure does not depend on the values: extract the shape
        // from a run on placeholders.
        let cs = new_cs(true);
        CfAugmentedCircuit::<G1, G2, SC> {
            poseidon: &poseidon,
            step,
            digest: Zero::zero(),
            i: 0,
            z0: alloc::vec![Zero::zero(); arity],
            zi: alloc::vec![Zero::zero(); arity],
            acc: RelaxedR1CSInstance {
                comm_e: Zero::zero(),
                u: Zero::zero(),
                comm_w: Zero::zero(),
                x: alloc::vec![Zero::zero()],
            },
            fresh: placeholder_fresh(),
            comm_t: Zero::zero(),
            cf_acc: CfRelaxedInstance::default_for(&cf_shape, &cf_key),
            cf: [
                CfFoldAdvice::placeholder(rows_w, rows_e),
                CfFoldAdvice::placeholder(rows_w, rows_e),
            ],
        }
        .synthesize(cs.clone())?;
        let shape = shape_from_cs(&cs)?;
        Ok((shape, cf_shape, cf_key))
    }

    /// Row counts of the CycleFold commitments to `W` and to `E`.
    pub fn cf_rows(&self) -> (usize, usize) {
        (
            self.cf_key.rows(self.cf_shape.num_vars),
            self.cf_key.rows(self.cf_shape.num_constraints),
        )
    }
}

fn placeholder_fresh<G1: SWCurveConfig>() -> R1CSInstance<Projective<G1>> {
    R1CSInstance {
        comm_w: Zero::zero(),
        x: alloc::vec![Zero::zero()],
    }
}

impl<G1, G2> CycleFoldAccumulator<G1, G2>
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
{
    /// The empty computation starting at `z0`.
    pub fn new(
        params: &CycleFoldParams<G1, G2>,
        z0: Vec<G1::ScalarField>,
    ) -> Result<Self, IvcError> {
        if z0.len() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        Ok(Self {
            i: 0,
            zi: z0.clone(),
            z0,
            acc: (
                RelaxedR1CSInstance::default_for(&params.shape),
                RelaxedR1CSWitness::default_for(&params.shape),
            ),
            last: (
                placeholder_fresh(),
                R1CSWitness {
                    w: alloc::vec![Zero::zero(); params.shape.num_vars],
                    r_w: Zero::zero(),
                },
            ),
            cf: (
                CfRelaxedInstance::default_for(&params.cf_shape, &params.cf_key),
                CfRelaxedWitness::default_for(&params.cf_shape),
            ),
        })
    }

    /// Executes `z_{i+1} = F(z_i)` and absorbs it. Memory use is independent
    /// of `i`.
    pub fn prove_step<SC: StepCircuit<G1::ScalarField>>(
        &mut self,
        params: &CycleFoldParams<G1, G2>,
        step: &SC,
        rng: &mut impl RngCore,
    ) -> Result<(), IvcError> {
        if step.arity() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        let (rows_w, rows_e) = params.cf_rows();

        // 1. Fold the last primary instance (natively in the circuit) and the
        //    two CycleFold instances that carry its commitment updates.
        let (folded, comm_t, advice) = if self.i == 0 {
            let placeholder = CfFoldAdvice::placeholder(rows_w, rows_e);
            (
                None,
                Projective::<G1>::zero(),
                [placeholder.clone(), placeholder],
            )
        } else {
            let mut sponge = PoseidonSponge::new(&params.poseidon);
            let mut t_bits = Vec::new();
            let (acc_u, acc_w, comm_t) = nifs_prove_with(
                &params.ck,
                &params.shape,
                &self.acc.0,
                &self.acc.1,
                &self.last.0,
                &self.last.1,
                rng,
                |comm_t| {
                    t_bits = primary_challenge::<G1>(
                        &mut sponge,
                        params.digest,
                        &self.acc.0,
                        &self.last.0,
                        comm_t,
                    );
                    odd_scalar(&t_bits)
                },
            )?;
            let delegated = [
                CycleFoldCircuit::<G1>::new(t_bits.clone(), self.acc.0.comm_w, self.last.0.comm_w),
                CycleFoldCircuit::<G1>::new(t_bits, self.acc.0.comm_e, comm_t),
            ];
            debug_assert_eq!(delegated[0].output(), acc_u.comm_w);
            debug_assert_eq!(delegated[1].output(), acc_u.comm_e);

            let mut input = Vec::new();
            absorb_cf_acc(&mut input, &self.cf.0);
            sponge.absorb(&input);
            let (mut cf_u, mut cf_w) = self.cf.clone();
            let mut advice = Vec::with_capacity(2);
            for statement in &delegated {
                let cs = new_cs(false);
                statement.synthesize(cs.clone())?;
                let (w, x) = assignment_from_cs(&cs)?;
                drop(cs);
                debug_assert_eq!(x, statement.io());
                let fresh = cf_commit(&params.cf_key, &w, x);
                let t = cf_cross_term(&params.cf_shape, &cf_u, &cf_w, &fresh, &w)?;
                let comm_t = params.cf_key.commit(&t);

                let mut input = Vec::new();
                absorb_cf_fresh(&mut input, &fresh);
                absorb_rows(&mut input, &comm_t);
                sponge.absorb(&input);
                let r: G2::ScalarField = odd_scalar(&squeeze_challenge(&mut sponge));

                cf_u = cf_fold_instance(&cf_u, &fresh, &comm_t, r);
                cf_w = cf_fold_witness(&cf_w, &w, &t, r);
                advice.push(CfFoldAdvice {
                    comm_w: fresh.comm_w,
                    comm_t,
                });
            }
            let advice: [_; 2] = advice.try_into().expect("two folds");
            (Some(((acc_u, acc_w), (cf_u, cf_w))), comm_t, advice)
        };

        // 2. The primary circuit: F plus the verification of fold (1).
        let cs = new_cs(false);
        let z_next = CfAugmentedCircuit::<G1, G2, SC> {
            poseidon: &params.poseidon,
            step,
            digest: params.digest,
            i: self.i,
            z0: self.z0.clone(),
            zi: self.zi.clone(),
            acc: self.acc.0.clone(),
            fresh: self.last.0.clone(),
            comm_t,
            cf_acc: self.cf.0.clone(),
            cf: advice,
        }
        .synthesize(cs.clone())?;
        let (w, x) = assignment_from_cs(&cs)?;
        drop(cs);
        self.last = commit_witness(&params.ck, w, x, rng);

        if let Some((acc, cf)) = folded {
            self.acc = acc;
            self.cf = cf;
        }
        self.zi = z_next;
        self.i += 1;
        Ok(())
    }

    /// Verifies that `z_i = F^i(z_0)` with the full (non-succinct) checks,
    /// in time independent of `i`.
    /// Overwrites every witness of the state with zeros.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.acc.1.wipe();
        self.last.1.wipe();
        self.cf.1.e.zeroize();
        self.cf.1.w.zeroize();
        self.z0.zeroize();
        self.zi.zeroize();
    }

    pub fn verify(&self, params: &CycleFoldParams<G1, G2>) -> Result<(), IvcError> {
        if self.i == 0 {
            return Err(IvcError::NoSteps);
        }
        if self.z0.len() != params.arity || self.zi.len() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        if self.last.0.x.len() != 1 || self.acc.0.x.len() != 1 || self.cf.0.x.len() != CF_IO_LEN {
            return Err(IvcError::StateHashMismatch);
        }
        let (rows_w, rows_e) = params.cf_rows();
        if self.cf.0.comm_w.len() != rows_w || self.cf.0.comm_e.len() != rows_e {
            return Err(FoldError::WitnessCommitmentMismatch.into());
        }

        // The last instance commits to the whole claimed state.
        let hash = state_hash::<G1, G2>(
            &params.poseidon,
            params.digest,
            self.i,
            &self.z0,
            &self.zi,
            &self.acc.0,
            &self.cf.0,
        );
        if self.last.0.x[0] != hash {
            return Err(IvcError::StateHashMismatch);
        }

        check_accumulator(&params.ck, &params.shape, &self.acc.0, &self.acc.1)?;
        params.shape.is_sat(&self.last.1.w, &self.last.0.x)?;
        if params.ck.commit_reference(&self.last.1.w, self.last.1.r_w) != self.last.0.comm_w {
            return Err(FoldError::WitnessCommitmentMismatch.into());
        }
        cf_check(&params.cf_key, &params.cf_shape, &self.cf.0, &self.cf.1)?;
        Ok(())
    }
}
