//! Step 3: the closing circuit on a real CycleFold accumulator.

use ark_ec::{short_weierstrass::Projective, PrimeGroup};
use ark_ff::{One, UniformRand};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};
use ark_std::test_rng;
use core_r1cs::ark_bridge::{assignment_from_cs, shape_from_cs};
use zeno_ivc::{
    cyclefold::{
        closing::{closing_scalars, ClosingCircuit},
        CycleFoldAccumulator, CycleFoldParams, CF_COLUMNS,
    },
    CubicStep,
};

type Bn254 = ark_bn254::g1::Config;
type Grumpkin = ark_grumpkin::GrumpkinConfig;
type Fr = ark_bn254::Fr;
type Fq = ark_bn254::Fq;

fn cs() -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    cs
}

#[test]
fn closing_circuit_on_a_real_accumulator() {
    let mut rng = test_rng();
    let step = CubicStep { rounds: 1 };
    let params = CycleFoldParams::<Bn254, Grumpkin>::setup(&step, b"closing", CF_COLUMNS).unwrap();
    let mut acc = CycleFoldAccumulator::new(&params, vec![Fr::from(3u64)]).unwrap();
    for _ in 0..3 {
        acc.prove_step(&params, &step, &mut rng).unwrap();
    }
    acc.verify(&params).unwrap();

    // Evaluation points of W̃ and Ẽ (10 variables each: 8 rows × 128 columns)
    // and the batching scalar, as the EVM's transcript would provide them.
    let point = |rng: &mut _| -> Vec<Fq> { (0..10).map(|_| Fq::rand(rng)).collect() };
    let (r_w, r_e, gamma) = (point(&mut rng), point(&mut rng), Fq::rand(&mut rng));
    let (cf_u, cf_w) = &acc.cf;
    let (row_weights, combined, _, _) =
        closing_scalars(&cf_w.w, &cf_w.e, CF_COLUMNS, &r_w, &r_e, gamma);
    let gens = params.cf_key.ck.gens.clone();
    let circuit = ClosingCircuit::<Bn254, Grumpkin> {
        poseidon: &params.poseidon,
        digest: params.digest,
        gens: &gens,
        i: acc.i,
        z0: acc.z0.clone(),
        zi: acc.zi.clone(),
        acc: acc.acc.0.clone(),
        cf_acc: cf_u.clone(),
        row_weights,
        combined,
    };
    assert!(circuit.holds());
    // The circuit's hash is the last instance's public input.
    assert_eq!(circuit.public_inputs()[0], acc.last.0.x[0]);

    let cs1 = cs();
    circuit.synthesize(cs1.clone()).unwrap();
    assert!(cs1.is_satisfied().unwrap());
    let (w, x) = assignment_from_cs(&cs1).unwrap();
    assert_eq!(x, circuit.public_inputs(), "public input layout");
    let shape = shape_from_cs(&cs1).unwrap();
    shape.is_sat(&w, &x).unwrap();
    let nnz = shape.a.nnz() + shape.b.nnz() + shape.c.nnz();
    println!(
        "closing circuit: {} constraints, {} variables, {} public inputs, {} non-zero entries",
        shape.num_constraints, shape.num_vars, shape.num_io, nnz
    );
    // max(m, 2n, non-zero) must fit the 2^20 powers of the public .ptau.
    assert!(shape.num_constraints.max(2 * shape.num_vars).max(nnz) <= 1 << 20);

    // A wrong combined row breaks the group equation.
    let mut forged = ClosingCircuit {
        combined: circuit.combined.clone(),
        ..circuit_clone(&circuit)
    };
    forged.combined[5] += Fq::one();
    assert!(!forged.holds());
    let cs2 = cs();
    forged.synthesize(cs2.clone()).unwrap();
    assert!(!cs2.is_satisfied().unwrap());

    // A wrong row (not the one the state hash commits to) breaks the hash.
    let mut forged = circuit_clone(&circuit);
    forged.cf_acc.comm_w[2] += Projective::<Grumpkin>::generator();
    let cs3 = cs();
    forged.synthesize(cs3.clone()).unwrap();
    let (_, x3) = assignment_from_cs(&cs3).unwrap();
    // Recomputing h from the forged rows changes h itself, which no longer
    // matches the last primary instance.
    assert_ne!(x3[0], acc.last.0.x[0]);
}

fn circuit_clone<'a>(
    c: &ClosingCircuit<'a, Bn254, Grumpkin>,
) -> ClosingCircuit<'a, Bn254, Grumpkin> {
    ClosingCircuit {
        poseidon: c.poseidon,
        digest: c.digest,
        gens: c.gens,
        i: c.i,
        z0: c.z0.clone(),
        zi: c.zi.clone(),
        acc: c.acc.clone(),
        cf_acc: c.cf_acc.clone(),
        row_weights: c.row_weights.clone(),
        combined: c.combined.clone(),
    }
}
