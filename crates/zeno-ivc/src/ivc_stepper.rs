//! The IVC prover/verifier state machine over a 2-cycle of curves.
//!
//! `P1` is the primary curve (application logic runs in its scalar field);
//! `P2` is the secondary curve, with base and scalar fields swapped.

use crate::{
    nova_ivc_circuit::{AugmentedCircuit, StepCircuit},
    step_circuits::TrivialStep,
};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{PrimeField, Zero};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core::fmt;
use core_r1cs::{
    ark_bridge::{assignment_from_cs, shape_from_cs},
    R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness,
};
use llull_folder::{
    check_accumulator, commit_witness, nifs_prove,
    transcript::{bits_to_field, poseidon_config, state_hash},
    CommitmentKey, FoldError, PublicParams,
};
use sha2::{Digest, Sha256};

/// Errors of the IVC layer.
#[derive(Clone, Debug)]
pub enum IvcError {
    Synthesis(SynthesisError),
    Fold(FoldError),
    /// A proof for zero steps carries no statement.
    NoSteps,
    /// The claimed `(i, z_0, z_i)` does not match the hash in the last instance.
    StateHashMismatch,
    /// The step circuit's arity differs from the one fixed at setup.
    ArityMismatch,
    /// A succinct argument in a compressed proof did not verify.
    InvalidSnark,
    /// Serialized prover state that is not a state of these parameters.
    MalformedState,
}

impl From<SynthesisError> for IvcError {
    fn from(e: SynthesisError) -> Self {
        Self::Synthesis(e)
    }
}

impl From<FoldError> for IvcError {
    fn from(e: FoldError) -> Self {
        Self::Fold(e)
    }
}

impl From<core_r1cs::R1CSError> for IvcError {
    fn from(e: core_r1cs::R1CSError) -> Self {
        Self::Fold(e.into())
    }
}

impl fmt::Display for IvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Synthesis(e) => write!(f, "circuit synthesis failed: {e}"),
            Self::Fold(e) => write!(f, "{e}"),
            Self::NoSteps => write!(f, "an IVC proof needs at least one step"),
            Self::StateHashMismatch => write!(f, "IVC state hash mismatch"),
            Self::ArityMismatch => write!(f, "step circuit arity mismatch"),
            Self::InvalidSnark => write!(f, "succinct argument verification failed"),
            Self::MalformedState => write!(f, "malformed or foreign prover state"),
        }
    }
}

/// Transparent public parameters of an IVC instance for one step function.
pub struct IvcParams<P1: SWCurveConfig, P2: SWCurveConfig>
where
    P1::BaseField: PrimeField,
    P2::BaseField: PrimeField,
{
    /// Shape of the primary augmented circuit (over `P1::ScalarField`).
    pub shape1: R1CSShape<P1::ScalarField>,
    /// Shape of the secondary augmented circuit (over `P2::ScalarField`).
    pub shape2: R1CSShape<P2::ScalarField>,
    /// Folding parameters for primary-circuit instances (committed on `P1`).
    pub pp1: PublicParams<Projective<P1>>,
    /// Folding parameters for secondary-circuit instances (committed on `P2`).
    pub pp2: PublicParams<Projective<P2>>,
    /// State arity of the step function.
    pub arity: usize,
}

/// The constant-size IVC state: a proof that `z_i = F^i(z_0)`.
///
/// Its size depends only on the circuit, never on the number of steps `i`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZenoAccumulator<P1: SWCurveConfig, P2: SWCurveConfig> {
    pub i: u64,
    pub z0: Vec<P1::ScalarField>,
    pub zi: Vec<P1::ScalarField>,
    /// Running accumulator of all primary-circuit instances.
    pub acc1: (
        RelaxedR1CSInstance<Projective<P1>>,
        RelaxedR1CSWitness<Projective<P1>>,
    ),
    /// Running accumulator of all but the last secondary-circuit instance.
    pub acc2: (
        RelaxedR1CSInstance<Projective<P2>>,
        RelaxedR1CSWitness<Projective<P2>>,
    ),
    /// The last secondary-circuit instance, not yet folded.
    pub last2: (R1CSInstance<Projective<P2>>, R1CSWitness<Projective<P2>>),
}

fn new_cs<F: PrimeField>(construct_matrices: bool) -> ConstraintSystemRef<F> {
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_mode(SynthesisMode::Prove { construct_matrices });
    cs
}

/// The state of the (trivial) secondary step function.
fn secondary_state<F: PrimeField>() -> Vec<F> {
    alloc::vec![F::zero()]
}

impl<P1, P2> IvcParams<P1, P2>
where
    P1: SWCurveConfig<BaseField = <P2 as ark_ec::CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as ark_ec::CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    /// Derives all parameters from the step circuit. No trusted setup.
    pub fn setup<SC: StepCircuit<P1::ScalarField>>(
        step: &SC,
        label: &[u8],
    ) -> Result<Self, IvcError> {
        let poseidon1 = poseidon_config::<P1::BaseField>();
        let poseidon2 = poseidon_config::<P2::BaseField>();
        let arity = step.arity();

        // The constraint structure does not depend on the inputs, so the
        // shapes are extracted from a run on placeholder values.
        let cs = new_cs(true);
        AugmentedCircuit::<P2, SC> {
            poseidon: &poseidon2,
            fold_in_base_case: false,
            step,
            digest: Zero::zero(),
            i: 0,
            z0: alloc::vec![Zero::zero(); arity],
            zi: alloc::vec![Zero::zero(); arity],
            acc: placeholder_relaxed(),
            fresh: placeholder_fresh(),
            comm_t: Zero::zero(),
        }
        .synthesize(cs.clone())?;
        let shape1 = shape_from_cs(&cs)?;

        let cs = new_cs(true);
        AugmentedCircuit::<P1, TrivialStep> {
            poseidon: &poseidon1,
            fold_in_base_case: true,
            step: &TrivialStep,
            digest: Zero::zero(),
            i: 0,
            z0: secondary_state(),
            zi: secondary_state(),
            acc: placeholder_relaxed(),
            fresh: placeholder_fresh(),
            comm_t: Zero::zero(),
        }
        .synthesize(cs.clone())?;
        let shape2 = shape_from_cs(&cs)?;

        // Keys are padded to a power of two so the final SNARK can open
        // the committed vectors as multilinear polynomials.
        let ck1 = CommitmentKey::<Projective<P1>>::setup(
            &[label, b"/primary"].concat(),
            shape1
                .num_vars
                .max(shape1.num_constraints)
                .next_power_of_two(),
        );
        let ck2 = CommitmentKey::<Projective<P2>>::setup(
            &[label, b"/secondary"].concat(),
            shape2
                .num_vars
                .max(shape2.num_constraints)
                .next_power_of_two(),
        );

        // One digest binds both shapes and both commitment keys; it is the
        // `vk` absorbed by every hash, embedded in both fields (248 bits).
        let mut bytes = Vec::new();
        let ser = "serializing to a Vec cannot fail";
        shape1.serialize_compressed(&mut bytes).expect(ser);
        shape2.serialize_compressed(&mut bytes).expect(ser);
        ck1.gens.serialize_compressed(&mut bytes).expect(ser);
        ck1.h.serialize_compressed(&mut bytes).expect(ser);
        ck2.gens.serialize_compressed(&mut bytes).expect(ser);
        ck2.h.serialize_compressed(&mut bytes).expect(ser);
        let mut hasher = Sha256::new();
        hasher.update(b"zeno-llull/ivc-digest/v1");
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update((arity as u64).to_le_bytes());
        hasher.update(&bytes);
        let hash = hasher.finalize();

        Ok(Self {
            shape1,
            shape2,
            pp1: PublicParams {
                ck: ck1,
                poseidon: poseidon1,
                digest: P1::BaseField::from_le_bytes_mod_order(&hash[..31]),
            },
            pp2: PublicParams {
                ck: ck2,
                poseidon: poseidon2,
                digest: P2::BaseField::from_le_bytes_mod_order(&hash[..31]),
            },
            arity,
        })
    }
}

fn placeholder_relaxed<P: SWCurveConfig>() -> RelaxedR1CSInstance<Projective<P>> {
    RelaxedR1CSInstance {
        comm_e: Zero::zero(),
        u: Zero::zero(),
        comm_w: Zero::zero(),
        x: alloc::vec![Zero::zero(); 2],
    }
}

fn placeholder_fresh<P: SWCurveConfig>() -> R1CSInstance<Projective<P>> {
    R1CSInstance {
        comm_w: Zero::zero(),
        x: alloc::vec![Zero::zero(); 2],
    }
}

impl<P1, P2> ZenoAccumulator<P1, P2>
where
    P1: SWCurveConfig<BaseField = <P2 as ark_ec::CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as ark_ec::CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    /// The empty computation starting at `z0`.
    pub fn new(params: &IvcParams<P1, P2>, z0: Vec<P1::ScalarField>) -> Result<Self, IvcError> {
        if z0.len() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        Ok(Self {
            i: 0,
            zi: z0.clone(),
            z0,
            acc1: (
                RelaxedR1CSInstance::default_for(&params.shape1),
                RelaxedR1CSWitness::default_for(&params.shape1),
            ),
            acc2: (
                RelaxedR1CSInstance::default_for(&params.shape2),
                RelaxedR1CSWitness::default_for(&params.shape2),
            ),
            last2: (
                placeholder_fresh(),
                R1CSWitness {
                    w: alloc::vec![Zero::zero(); params.shape2.num_vars],
                    r_w: Zero::zero(),
                },
            ),
        })
    }

    /// Executes one more step `z_{i+1} = F(z_i)` and absorbs it into the
    /// accumulator. Memory use is independent of `i`.
    pub fn prove_step<SC: StepCircuit<P1::ScalarField>>(
        &mut self,
        params: &IvcParams<P1, P2>,
        step: &SC,
        rng: &mut impl RngCore,
    ) -> Result<(), IvcError> {
        if step.arity() != params.arity {
            return Err(IvcError::ArityMismatch);
        }

        // 1. Fold the last secondary instance into the secondary accumulator.
        //    At step 0 it is a placeholder and the circuit ignores it.
        let (acc2_next, comm_t2) = if self.i == 0 {
            (None, Projective::<P2>::zero())
        } else {
            let (u, w, t) = nifs_prove(
                &params.pp2,
                &params.shape2,
                &self.acc2.0,
                &self.acc2.1,
                &self.last2.0,
                &self.last2.1,
                rng,
            )?;
            (Some((u, w)), t)
        };

        // 2. Primary circuit: runs F and verifies fold (1) in-circuit.
        let cs = new_cs(false);
        let z_next = AugmentedCircuit::<P2, SC> {
            poseidon: &params.pp2.poseidon,
            fold_in_base_case: false,
            step,
            digest: params.pp2.digest,
            i: self.i,
            z0: self.z0.clone(),
            zi: self.zi.clone(),
            acc: self.acc2.0.clone(),
            fresh: self.last2.0.clone(),
            comm_t: comm_t2,
        }
        .synthesize(cs.clone())?;
        let (w, x) = assignment_from_cs(&cs)?;
        drop(cs);
        let (u1, w1) = commit_witness(&params.pp1.ck, w, x, rng);

        // 3. Fold the new primary instance into the primary accumulator.
        let (acc1_u, acc1_w, comm_t1) = nifs_prove(
            &params.pp1,
            &params.shape1,
            &self.acc1.0,
            &self.acc1.1,
            &u1,
            &w1,
            rng,
        )?;

        // 4. Secondary circuit: verifies fold (3) in-circuit.
        let cs = new_cs(false);
        AugmentedCircuit::<P1, TrivialStep> {
            poseidon: &params.pp1.poseidon,
            fold_in_base_case: true,
            step: &TrivialStep,
            digest: params.pp1.digest,
            i: self.i,
            z0: secondary_state(),
            zi: secondary_state(),
            acc: self.acc1.0.clone(),
            fresh: u1,
            comm_t: comm_t1,
        }
        .synthesize(cs.clone())?;
        let (w, x) = assignment_from_cs(&cs)?;
        drop(cs);
        self.last2 = commit_witness(&params.pp2.ck, w, x, rng);

        self.acc1 = (acc1_u, acc1_w);
        if let Some(acc2) = acc2_next {
            self.acc2 = acc2;
        }
        self.zi = z_next;
        self.i += 1;
        Ok(())
    }

    /// Overwrites every witness of the state with zeros: call it (or let a
    /// service's session drop call it) once the state is no longer needed.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.acc1.1.wipe();
        self.acc2.1.wipe();
        self.last2.1.wipe();
        self.z0.zeroize();
        self.zi.zeroize();
    }

    /// Verifies that `z_i = F^i(z_0)`, in time independent of `i`.
    pub fn verify(&self, params: &IvcParams<P1, P2>) -> Result<(), IvcError> {
        if self.i == 0 {
            return Err(IvcError::NoSteps);
        }
        if self.z0.len() != params.arity || self.zi.len() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        if self.last2.0.x.len() != 2 || self.acc1.0.x.len() != 2 || self.acc2.0.x.len() != 2 {
            return Err(IvcError::StateHashMismatch);
        }

        // The last secondary instance commits to the whole claimed state.
        let hash1: P2::ScalarField = bits_to_field(&state_hash(
            &params.pp2.poseidon,
            params.pp2.digest,
            self.i,
            &self.z0,
            &self.zi,
            &self.acc2.0,
        ));
        let hash2: P2::ScalarField = bits_to_field(&state_hash(
            &params.pp1.poseidon,
            params.pp1.digest,
            self.i,
            &secondary_state(),
            &secondary_state(),
            &self.acc1.0,
        ));
        if self.last2.0.x[0] != hash1 || self.last2.0.x[1] != hash2 {
            return Err(IvcError::StateHashMismatch);
        }

        // Both accumulators and the last instance are satisfied.
        check_accumulator(&params.pp1.ck, &params.shape1, &self.acc1.0, &self.acc1.1)?;
        check_accumulator(&params.pp2.ck, &params.shape2, &self.acc2.0, &self.acc2.1)?;
        params.shape2.is_sat(&self.last2.1.w, &self.last2.0.x)?;
        if params
            .pp2
            .ck
            .commit_reference(&self.last2.1.w, self.last2.1.r_w)
            != self.last2.0.comm_w
        {
            return Err(FoldError::WitnessCommitmentMismatch.into());
        }
        Ok(())
    }

    /// Serializes the prover state, prefixed with [`STATE_MAGIC`] and
    /// [`STATE_VERSION`], so that a computation can be paused and resumed
    /// (possibly on another machine) with [`Self::from_bytes`].
    ///
    /// **The state holds the folded witnesses**: it is as secret as the
    /// witnesses themselves and must be stored accordingly (encrypted at
    /// rest, never published). Only finalized proofs are zero-knowledge.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.compressed_size());
        out.extend_from_slice(&STATE_MAGIC);
        out.push(STATE_VERSION);
        self.serialize_compressed(&mut out)
            .expect("serializing to a Vec cannot fail");
        out
    }

    /// Restores a state written by [`Self::to_bytes`] for the same
    /// parameters. Everything is checked before the state is accepted: the
    /// format, every vector length against the circuit shapes and, after at
    /// least one step, the full validity of the state ([`Self::verify`]).
    pub fn from_bytes(params: &IvcParams<P1, P2>, bytes: &[u8]) -> Result<Self, IvcError> {
        let body = bytes
            .strip_prefix(&STATE_MAGIC[..])
            .and_then(|rest| rest.strip_prefix(&[STATE_VERSION]))
            .ok_or(IvcError::MalformedState)?;
        if !core_r1cs::layout::fits(body, &Self::layout()) {
            return Err(IvcError::MalformedState);
        }
        let state = Self::deserialize_compressed(body).map_err(|_| IvcError::MalformedState)?;
        let (s1, s2) = (&params.shape1, &params.shape2);
        let shapes_ok = state.z0.len() == params.arity
            && state.zi.len() == params.arity
            && state.acc1.0.x.len() == s1.num_io
            && state.acc1.1.w.len() == s1.num_vars
            && state.acc1.1.e.len() == s1.num_constraints
            && state.acc2.0.x.len() == s2.num_io
            && state.acc2.1.w.len() == s2.num_vars
            && state.acc2.1.e.len() == s2.num_constraints
            && state.last2.0.x.len() == s2.num_io
            && state.last2.1.w.len() == s2.num_vars;
        if !shapes_ok {
            return Err(IvcError::MalformedState);
        }
        if state.i == 0 {
            // Nothing folded yet: the only valid state is the initial one.
            if Self::new(params, state.z0.clone())?.to_bytes() != bytes {
                return Err(IvcError::MalformedState);
            }
        } else {
            state.verify(params)?;
        }
        Ok(state)
    }
}

impl<P1: SWCurveConfig, P2: SWCurveConfig> ZenoAccumulator<P1, P2> {
    /// The serialized layout, checked before deserializing (see
    /// [`core_r1cs::layout`]).
    fn layout() -> Vec<core_r1cs::layout::Item> {
        use core_r1cs::layout::Item::{Fixed, Vec as V};
        let (f1, f2) = (
            P1::ScalarField::zero().compressed_size(),
            P2::ScalarField::zero().compressed_size(),
        );
        let (g1, g2) = (
            Projective::<P1>::zero().compressed_size(),
            Projective::<P2>::zero().compressed_size(),
        );
        alloc::vec![
            Fixed(8),
            V(f1),
            V(f1),
            // acc1: instance (comm_E, u, comm_W, x), witness (E, r_E, W, r_W)
            Fixed(g1),
            Fixed(f1),
            Fixed(g1),
            V(f1),
            V(f1),
            Fixed(f1),
            V(f1),
            Fixed(f1),
            // acc2
            Fixed(g2),
            Fixed(f2),
            Fixed(g2),
            V(f2),
            V(f2),
            Fixed(f2),
            V(f2),
            Fixed(f2),
            // last2: instance (comm_W, x), witness (W, r_W)
            Fixed(g2),
            V(f2),
            V(f2),
            Fixed(f2),
        ]
    }
}

/// Magic bytes of a serialized prover state ([`ZenoAccumulator::to_bytes`]).
pub const STATE_MAGIC: [u8; 3] = *b"ZLS";
/// Format version of a serialized prover state.
pub const STATE_VERSION: u8 = 1;
