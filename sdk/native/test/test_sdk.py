"""End-to-end test of the native SDK through its generated Python bindings.

The same Rust library backs the Swift and Kotlin bindings, so this exercises
the exact code path an iOS or Android app would call.
"""
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "sdk/native/dist/python"))
import zenollull  # noqa: E402

FIXTURES = ROOT / "crates/sdk-bindings/fixtures"
r1cs = (FIXTURES / "step.r1cs").read_bytes()
witnesses = [(FIXTURES / f"step{i}.wtns").read_bytes() for i in range(3)]


def expect_error(kind, call):
    try:
        call()
    except kind:
        return
    raise AssertionError(f"expected {kind.__name__}")


prover = zenollull.Prover(r1cs, ["3"])
assert prover.steps() == 0 and prover.state() == ["3"]

# A witness for a later step does not continue from the current state.
expect_error(zenollull.ZenoError.InvalidInput, lambda: prover.prove_step(witnesses[1]))
expect_error(zenollull.ZenoError.InvalidInput, lambda: prover.prove_step(b"junk"))
expect_error(zenollull.ZenoError.InvalidInput, lambda: zenollull.Prover(r1cs, ["x"]))
expect_error(zenollull.ZenoError.InvalidInput, lambda: zenollull.Prover(r1cs[:50], ["3"]))

start = time.time()
for wtns in witnesses:
    prover.prove_step(wtns)
print(f"prover   : {1000 * (time.time() - start) / 3:.0f} ms / step")
prover.verify()
assert prover.steps() == 3
assert prover.state() == ["130308420719099"]

proof = prover.finalize()
print(f"proof    : {len(proof)} bytes")
assert len(proof) < 16 * 1024

verifier = zenollull.Verifier(r1cs)
statement = verifier.verify(proof)
assert (statement.steps, statement.z0, statement.zi) == (3, ["3"], ["130308420719099"])

tampered = bytearray(proof)
tampered[len(tampered) // 2] ^= 1
expect_error(zenollull.ZenoError.VerificationFailed, lambda: verifier.verify(bytes(tampered)))
expect_error(zenollull.ZenoError.VerificationFailed, lambda: verifier.verify(b""))
assert verifier.verifications() == 3

expect_error(
    zenollull.ZenoError.License,
    lambda: zenollull.verify_license("zl1.YQ.Yg", "00" * 32, int(time.time())),
)
if len(sys.argv) == 3:
    lic = zenollull.verify_license(sys.argv[1], sys.argv[2], int(time.time()))
    assert lic.customer == "ci"
    print(f"license  : {lic.customer} / {lic.plan}")
    expect_error(
        zenollull.ZenoError.License,
        lambda: zenollull.verify_license(sys.argv[1], sys.argv[2], 4_000_000_000),
    )
print("OK")
