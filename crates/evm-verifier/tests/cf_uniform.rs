//! `contracts/ZenoCycleFoldShape.sol` holds the CycleFold matrices the EVM
//! verifier evaluates; it must be the encoding of the circuit in this tree.
//! `ZENO_WRITE_CF_SHAPE=1 cargo test -p evm-verifier --test cf_uniform`
//! rewrites it.

use evm_verifier::cf_uniform;

#[test]
fn the_solidity_library_matches_the_circuit() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/ZenoCycleFoldShape.sol"
    );
    let expected = cf_uniform::bn254().solidity_library();
    if std::env::var_os("ZENO_WRITE_CF_SHAPE").is_some() {
        std::fs::write(path, &expected).expect("writable contracts directory");
    }
    let actual = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        actual == expected,
        "{path} is stale: rerun with ZENO_WRITE_CF_SHAPE=1"
    );
}
