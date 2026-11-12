//! End-to-end tests of the CycleFold IVC (step 1 and step 2 of the EVM
//! finalization plan) on both curve cycles.

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig, PrimeGroup,
};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use core_r1cs::ark_bridge::assignment_from_cs;
use llull_folder::FoldError;
use zeno_ivc::{
    cyclefold::{
        hyrax::{cf_check, cf_commit, cf_cross_term, cf_fold_instance, cf_fold_witness},
        CycleFoldAccumulator, CycleFoldCircuit, CycleFoldParams,
    },
    CubicStep, IvcError,
};

type Bn254 = ark_bn254::g1::Config;
type Grumpkin = ark_grumpkin::GrumpkinConfig;

fn run<G1, G2>(steps: u64, cols: usize) -> (CycleFoldParams<G1, G2>, CycleFoldAccumulator<G1, G2>)
where
    G1: SWCurveConfig<BaseField = <G2 as CurveConfig>::ScalarField>,
    G2: SWCurveConfig<BaseField = <G1 as CurveConfig>::ScalarField>,
    G1::BaseField: PrimeField,
    G2::BaseField: PrimeField + Absorb,
{
    let mut rng = test_rng();
    let step = CubicStep { rounds: 8 };
    let params = CycleFoldParams::<G1, G2>::setup(&step, b"test", cols).unwrap();
    let z0 = G1::ScalarField::from(3u64);
    let mut acc = CycleFoldAccumulator::new(&params, vec![z0]).unwrap();
    assert!(matches!(acc.verify(&params), Err(IvcError::NoSteps)));

    let mut expected = z0;
    let mut sizes = Vec::new();
    for _ in 0..steps {
        acc.prove_step(&params, &step, &mut rng).unwrap();
        expected = step.eval(expected);
        acc.verify(&params).unwrap();
        assert_eq!(acc.zi, vec![expected]);
        sizes.push(acc.compressed_size());
    }
    assert_eq!(acc.i, steps);
    // The proof state has a constant size in the number of steps.
    assert!(sizes.windows(2).all(|p| p[0] == p[1]));
    (params, acc)
}

#[test]
fn cyclefold_ivc_bn254_grumpkin() {
    let (params, acc) = run::<Bn254, Grumpkin>(5, zeno_ivc::cyclefold::CF_COLUMNS);
    assert_eq!(params.cf_rows(), (8, 8));
    let (rows_w, rows_e) = params.cf_rows();
    println!(
        "BN254/Grumpkin, 128 columns: primary {} constraints; CycleFold {} constraints, {} + {} rows",
        params.shape.num_constraints, params.cf_shape.num_constraints, rows_w, rows_e
    );
    // Both CycleFold folds per step were really accumulated: u = Σ r_k ≠ 0.
    assert!(!acc.cf.0.u.is_zero());
}

#[test]
fn cyclefold_ivc_pallas_vesta() {
    run::<ark_pallas::PallasConfig, ark_vesta::VestaConfig>(3, 1024);
}

#[test]
fn a_single_row_is_plain_pedersen() {
    // cols ≥ M: one commitment per vector, i.e. the usual Nova accumulator.
    let (params, _) = run::<Bn254, Grumpkin>(3, 2048);
    assert_eq!(params.cf_rows(), (1, 1));
}

#[test]
fn tampering_is_rejected() {
    type F = ark_bn254::Fr;
    let (params, acc) = run::<Bn254, Grumpkin>(3, 1024);

    // The claimed state.
    let mut bad = acc.clone();
    bad.zi[0] += F::one();
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.i += 1;
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));

    // The primary accumulator: its instance is bound by the state hash, its
    // witness by the commitments.
    let mut bad = acc.clone();
    bad.acc.0.comm_w += Projective::<Bn254>::generator();
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.acc.1.w[0] += F::one();
    assert!(bad.verify(&params).is_err());

    // The last instance.
    let mut bad = acc.clone();
    bad.last.1.w[3] += F::one();
    assert!(bad.verify(&params).is_err());

    // The CycleFold accumulator: rows and scalars are bound by the state
    // hash, the witness by the row commitments and the relation.
    let mut bad = acc.clone();
    bad.cf.0.comm_e[0] += Projective::<Grumpkin>::generator();
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.cf.0.x[5] += ark_bn254::Fq::one();
    assert!(matches!(
        bad.verify(&params),
        Err(IvcError::StateHashMismatch)
    ));
    let mut bad = acc.clone();
    bad.cf.1.w[10] += ark_bn254::Fq::one();
    assert!(bad.verify(&params).is_err());
    let mut bad = acc;
    bad.cf.1.e[0] += ark_bn254::Fq::one();
    assert!(bad.verify(&params).is_err());
}

#[test]
fn a_wrong_delegated_fold_poisons_the_cyclefold_accumulator() {
    // A prover that claims a wrong W' (= a wrong CycleFold output) cannot
    // produce a satisfying CycleFold instance; once folded, the accumulator
    // is unsatisfiable and the decider rejects.
    let mut rng = test_rng();
    let step = CubicStep { rounds: 1 };
    let (_, cf_shape, cf_key) =
        CycleFoldParams::<Bn254, Grumpkin>::shapes(&step, b"test", 256).unwrap();
    let statement = CycleFoldCircuit::<Bn254>::new(
        (0..zeno_ivc::cyclefold::T_BITS)
            .map(|_| bool::rand(&mut rng))
            .collect(),
        Projective::rand(&mut rng),
        Projective::rand(&mut rng),
    );
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });
    statement.synthesize(cs.clone()).unwrap();
    let (w, mut x) = assignment_from_cs(&cs).unwrap();

    let fold = |x: Vec<ark_bn254::Fq>| {
        let acc = zeno_ivc::cyclefold::hyrax::CfRelaxedInstance::default_for(&cf_shape, &cf_key);
        let acc_w = zeno_ivc::cyclefold::hyrax::CfRelaxedWitness::default_for(&cf_shape);
        let fresh = cf_commit(&cf_key, &w, x);
        let t = cf_cross_term(&cf_shape, &acc, &acc_w, &fresh, &w).unwrap();
        let comm_t = cf_key.commit(&t);
        let r = ark_bn254::Fq::from(u128::rand(&mut test_rng()));
        (
            cf_fold_instance(&acc, &fresh, &comm_t, r),
            cf_fold_witness(&acc_w, &w, &t, r),
        )
    };
    let (u, uw) = fold(x.clone());
    cf_check(&cf_key, &cf_shape, &u, &uw).unwrap();

    let wrong: ark_bn254::G1Affine = (statement.output() + Projective::<Bn254>::generator()).into();
    x[5] = wrong.x;
    x[6] = wrong.y;
    let (u, uw) = fold(x);
    assert!(matches!(
        cf_check(&cf_key, &cf_shape, &u, &uw),
        Err(FoldError::R1CS(_))
    ));
}

#[test]
fn circuit_size_against_columns() {
    // The trade-off of the row commitments: fewer columns make the final
    // opening cheaper but add one scalar multiplication per row and fold to
    // every step. Printed for the record; asserted to be monotone.
    let step = CubicStep { rounds: 1 };
    let mut last = usize::MAX;
    let mut at_128 = (0, 0);
    for cols in [64, 128, 256, 512, 1024, 2048] {
        let (shape, cf_shape, cf_key) =
            CycleFoldParams::<Bn254, Grumpkin>::shapes(&step, b"size", cols).unwrap();
        let rows = (
            cf_key.rows(cf_shape.num_vars),
            cf_key.rows(cf_shape.num_constraints),
        );
        let nnz = shape.a.nnz() + shape.b.nnz() + shape.c.nnz();
        println!(
            "cols {cols:>4}: rows W/E {:>2}/{:>2}, primary circuit {:>6} constraints, {:>6} variables, {:>7} non-zero entries",
            rows.0, rows.1, shape.num_constraints, shape.num_vars, nnz
        );
        assert!(shape.num_constraints <= last);
        last = shape.num_constraints;
        if cols == 128 {
            at_128 = (shape.num_constraints, nnz);
        }
    }
    // With the low-weight gadgets (measured: 66 791 constraints and 468 322
    // non-zero entries at 128 columns, against 95 714 / 3.97 M with the
    // arkworks gadgets).
    assert!(at_128.0 < 70_000 && at_128.1 < 500_000, "{at_128:?}");
}
