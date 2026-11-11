//! The final IVC proofs and their verifiers.

use crate::spartan::{self, SpartanProof};
use alloc::vec::Vec;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core_r1cs::{R1CSInstance, RelaxedR1CSInstance, RelaxedR1CSWitness};
use llull_folder::{
    check_accumulator, nifs_prove, nifs_prove_relaxed, nifs_verify, nifs_verify_relaxed,
    sample_relaxed,
    transcript::{bits_to_field, state_hash},
};
use zeno_ivc::{IvcError, IvcParams, ZenoAccumulator};

type Relaxed<P> = RelaxedR1CSInstance<Projective<P>>;
type Witness<P> = RelaxedR1CSWitness<Projective<P>>;

/// The public part shared by both proof variants: the claim `z_i = F^i(z_0)`
/// and everything needed to re-derive the two masked accumulator instances.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FoldedStatement<P1: SWCurveConfig, P2: SWCurveConfig> {
    pub i: u64,
    pub z0: Vec<P1::ScalarField>,
    pub zi: Vec<P1::ScalarField>,
    /// Primary accumulator instance, as bound by the state hash.
    pub acc1: Relaxed<P1>,
    /// Secondary accumulator instance, as bound by the state hash.
    pub acc2: Relaxed<P2>,
    /// Last secondary instance and the cross-term folding it into `acc2`.
    pub last2: R1CSInstance<Projective<P2>>,
    pub comm_t_last: Projective<P2>,
    /// Random masking instances and their cross-term commitments.
    pub mask1: Relaxed<P1>,
    pub comm_t1: Projective<P1>,
    pub mask2: Relaxed<P2>,
    pub comm_t2: Projective<P2>,
}

impl<P1, P2> FoldedStatement<P1, P2>
where
    P1: SWCurveConfig<BaseField = <P2 as CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    /// Folds and masks the prover state, returning the statement together
    /// with the openings of the two masked accumulators.
    #[allow(clippy::type_complexity)]
    fn fold(
        params: &IvcParams<P1, P2>,
        acc: &ZenoAccumulator<P1, P2>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, Witness<P1>, Witness<P2>), IvcError> {
        if acc.i == 0 {
            return Err(IvcError::NoSteps);
        }
        // Fold the pending secondary instance, so only accumulators remain.
        let (u2, w2, comm_t_last) = nifs_prove(
            &params.pp2,
            &params.shape2,
            &acc.acc2.0,
            &acc.acc2.1,
            &acc.last2.0,
            &acc.last2.1,
            rng,
        )?;

        // Mask both accumulators with random satisfying relaxed pairs.
        let (mask1, mask1_w) = sample_relaxed(&params.pp1.ck, &params.shape1, rng);
        let (_, w1, comm_t1) = nifs_prove_relaxed(
            &params.pp1,
            &params.shape1,
            &acc.acc1.0,
            &acc.acc1.1,
            &mask1,
            &mask1_w,
            rng,
        )?;
        let (mask2, mask2_w) = sample_relaxed(&params.pp2.ck, &params.shape2, rng);
        let (_, w2, comm_t2) =
            nifs_prove_relaxed(&params.pp2, &params.shape2, &u2, &w2, &mask2, &mask2_w, rng)?;

        let statement = Self {
            i: acc.i,
            z0: acc.z0.clone(),
            zi: acc.zi.clone(),
            acc1: acc.acc1.0.clone(),
            acc2: acc.acc2.0.clone(),
            last2: acc.last2.0.clone(),
            comm_t_last,
            mask1,
            comm_t1,
            mask2,
            comm_t2,
        };
        Ok((statement, w1, w2))
    }

    /// Checks the state hashes and re-derives, from public data only, the
    /// two masked accumulator instances whose satisfiability remains to be
    /// shown.
    pub fn masked_instances(
        &self,
        params: &IvcParams<P1, P2>,
    ) -> Result<(Relaxed<P1>, Relaxed<P2>), IvcError> {
        if self.i == 0 {
            return Err(IvcError::NoSteps);
        }
        if self.z0.len() != params.arity || self.zi.len() != params.arity {
            return Err(IvcError::ArityMismatch);
        }
        let io_ok = |n: usize| n == 2;
        if !(io_ok(self.acc1.x.len())
            && io_ok(self.acc2.x.len())
            && io_ok(self.last2.x.len())
            && io_ok(self.mask1.x.len())
            && io_ok(self.mask2.x.len()))
        {
            return Err(IvcError::StateHashMismatch);
        }

        // The last instance commits to the claimed state and accumulators.
        let hash1: P2::ScalarField = bits_to_field(&state_hash(
            &params.pp2.poseidon,
            params.pp2.digest,
            self.i,
            &self.z0,
            &self.zi,
            &self.acc2,
        ));
        let zero = [P1::BaseField::from(0u64)];
        let hash2: P2::ScalarField = bits_to_field(&state_hash(
            &params.pp1.poseidon,
            params.pp1.digest,
            self.i,
            &zero,
            &zero,
            &self.acc1,
        ));
        if self.last2.x[0] != hash1 || self.last2.x[1] != hash2 {
            return Err(IvcError::StateHashMismatch);
        }

        let (pp1, pp2) = (&params.pp1, &params.pp2);
        let u2 = nifs_verify(
            &pp2.poseidon,
            pp2.digest,
            &self.acc2,
            &self.last2,
            &self.comm_t_last,
        );
        let u2 = nifs_verify_relaxed(&pp2.poseidon, pp2.digest, &u2, &self.mask2, &self.comm_t2);
        let u1 = nifs_verify_relaxed(
            &pp1.poseidon,
            pp1.digest,
            &self.acc1,
            &self.mask1,
            &self.comm_t1,
        );
        Ok((u1, u2))
    }
}

/// A zero-knowledge proof that `z_i = F^i(z_0)` which ships the masked
/// witnesses: simple, but linear in the circuit size.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkIvcProof<P1: SWCurveConfig, P2: SWCurveConfig> {
    pub statement: FoldedStatement<P1, P2>,
    /// Openings of the fully folded, masked accumulators.
    pub w1: Witness<P1>,
    pub w2: Witness<P2>,
}

/// A succinct zero-knowledge proof that `z_i = F^i(z_0)`: the masked
/// witnesses are replaced by two transparent SNARKs.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedIvcProof<P1: SWCurveConfig, P2: SWCurveConfig> {
    pub statement: FoldedStatement<P1, P2>,
    pub snark1: SpartanProof<Projective<P1>>,
    pub snark2: SpartanProof<Projective<P2>>,
}

impl<P1, P2> ZkIvcProof<P1, P2>
where
    P1: SWCurveConfig<BaseField = <P2 as CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    /// Finalizes an IVC run into a zero-knowledge proof.
    pub fn prove(
        params: &IvcParams<P1, P2>,
        acc: &ZenoAccumulator<P1, P2>,
        rng: &mut impl RngCore,
    ) -> Result<Self, IvcError> {
        let (statement, w1, w2) = FoldedStatement::fold(params, acc, rng)?;
        Ok(Self { statement, w1, w2 })
    }

    /// Verifies the proof in time independent of the number of steps.
    pub fn verify(&self, params: &IvcParams<P1, P2>) -> Result<(), IvcError> {
        let (u1, u2) = self.statement.masked_instances(params)?;
        check_accumulator(&params.pp1.ck, &params.shape1, &u1, &self.w1)?;
        check_accumulator(&params.pp2.ck, &params.shape2, &u2, &self.w2)?;
        Ok(())
    }

    /// Compresses the masked witnesses into two succinct arguments.
    pub fn compress(
        self,
        params: &IvcParams<P1, P2>,
    ) -> Result<CompressedIvcProof<P1, P2>, IvcError> {
        let (u1, u2) = self.statement.masked_instances(params)?;
        let (pp1, pp2) = (&params.pp1, &params.pp2);
        let snark1 = spartan::prove(&pp1.ck, &pp1.digest, &params.shape1, &u1, &self.w1);
        let snark2 = spartan::prove(&pp2.ck, &pp2.digest, &params.shape2, &u2, &self.w2);
        Ok(CompressedIvcProof {
            statement: self.statement,
            snark1,
            snark2,
        })
    }
}

impl<P1, P2> CompressedIvcProof<P1, P2>
where
    P1: SWCurveConfig<BaseField = <P2 as CurveConfig>::ScalarField>,
    P2: SWCurveConfig<BaseField = <P1 as CurveConfig>::ScalarField>,
    P1::BaseField: PrimeField + Absorb,
    P2::BaseField: PrimeField + Absorb,
{
    /// Finalizes an IVC run into a succinct zero-knowledge proof.
    pub fn prove(
        params: &IvcParams<P1, P2>,
        acc: &ZenoAccumulator<P1, P2>,
        rng: &mut impl RngCore,
    ) -> Result<Self, IvcError> {
        ZkIvcProof::prove(params, acc, rng)?.compress(params)
    }

    /// Verifies the proof in time independent of the number of steps.
    pub fn verify(&self, params: &IvcParams<P1, P2>) -> Result<(), IvcError> {
        let (u1, u2) = self.statement.masked_instances(params)?;
        let (pp1, pp2) = (&params.pp1, &params.pp2);
        if !spartan::verify(&pp1.ck, &pp1.digest, &params.shape1, &u1, &self.snark1)
            || !spartan::verify(&pp2.ck, &pp2.digest, &params.shape2, &u2, &self.snark2)
        {
            return Err(IvcError::InvalidSnark);
        }
        Ok(())
    }
}
