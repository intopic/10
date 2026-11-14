"""End-to-end test of the native SDK through its generated Python bindings.

The same Rust library backs the Swift and Kotlin bindings, so this exercises
the exact code path an iOS or Android app would call.
"""
import pathlib
import sys
import time

# The prover runs only under a license. A library built without a vendor key
# (as in CI) checks against the public development key:
#   test_sdk.py "$(zeno-license issue --dev --customer ci --plan enterprise --days 1)" \
#               ["$(zeno-license issue --dev ... --max-steps 2)" [FOREIGN_LICENSE]]
if len(sys.argv) < 2:
    sys.exit("usage: test_sdk.py LICENSE [QUOTA_LICENSE [FOREIGN_LICENSE]]")
LICENSE = sys.argv[1]

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


prover = zenollull.Prover(LICENSE, r1cs, ["3"])
assert prover.steps() == 0 and prover.state() == ["3"]

# A witness for a later step does not continue from the current state.
expect_error(zenollull.ZenoError.InvalidInput, lambda: prover.prove_step(witnesses[1]))
expect_error(zenollull.ZenoError.InvalidInput, lambda: prover.prove_step(b"junk"))
expect_error(zenollull.ZenoError.InvalidInput, lambda: zenollull.Prover(LICENSE, r1cs, ["x"]))
expect_error(zenollull.ZenoError.InvalidInput, lambda: zenollull.Prover(LICENSE, r1cs[:50], ["3"]))

start = time.time()
for wtns in witnesses:
    prover.prove_step(wtns)
print(f"prover   : {1000 * (time.time() - start) / 3:.0f} ms / step")
prover.verify()
assert prover.steps() == 3
assert prover.state() == ["130308420719099"]

# Pause and resume: the saved state continues the same computation.
saved = prover.save_state()
resumed = zenollull.Prover.resume(LICENSE, r1cs, saved)
assert resumed.steps() == 3 and resumed.state() == prover.state()
corrupted = bytearray(saved)
corrupted[-40] ^= 1
expect_error(zenollull.ZenoError.VerificationFailed,
             lambda: zenollull.Prover.resume(LICENSE, r1cs, bytes(corrupted)))
print(f"state    : {len(saved)} bytes, resumed")

proof = prover.finalize()
print(f"proof    : {len(proof)} bytes")
assert len(proof) < 16 * 1024
assert proof[:4] == b"ZLP\x01"

verifier = zenollull.Verifier(r1cs)
statement = verifier.verify(proof)
assert (statement.steps, statement.z0, statement.zi) == (3, ["3"], ["130308420719099"])

tampered = bytearray(proof)
tampered[len(tampered) // 2] ^= 1
expect_error(zenollull.ZenoError.VerificationFailed, lambda: verifier.verify(bytes(tampered)))
expect_error(zenollull.ZenoError.VerificationFailed, lambda: verifier.verify(b""))
future = bytearray(proof)
future[3] = 2
expect_error(zenollull.ZenoError.VerificationFailed, lambda: verifier.verify(bytes(future)))
assert verifier.verifications() == 4

# License keys are checked against the vendor key compiled into the library;
# the caller cannot supply a key or a clock of its own.
expect_error(zenollull.ZenoError.License, lambda: zenollull.verify_license("zl1.YQ.Yg"))
lic = zenollull.verify_license(LICENSE)
assert lic.customer == "ci" and lic.max_steps is None
print(f"license  : {lic.customer} / {lic.plan}" + (" (development build)" if lic.development_build else ""))
# No prover without a license or with a forged one.
expect_error(zenollull.ZenoError.License, lambda: zenollull.Prover("", r1cs, ["3"]))
expect_error(zenollull.ZenoError.License, lambda: zenollull.Prover(LICENSE[:-4] + "AAAA", r1cs, ["3"]))
if len(sys.argv) > 3:
    # Signed by another key than the one this library was built with.
    expect_error(zenollull.ZenoError.License, lambda: zenollull.Prover(sys.argv[3], r1cs, ["3"]))
if len(sys.argv) > 2:
    # A quota of two steps: the third step is refused.
    assert zenollull.verify_license(sys.argv[2]).max_steps == 2
    limited = zenollull.Prover(sys.argv[2], r1cs, ["3"])
    limited.prove_step(witnesses[0])
    limited.prove_step(witnesses[1])
    expect_error(zenollull.ZenoError.License, lambda: limited.prove_step(witnesses[2]))
    assert limited.steps() == 2
    print("quota    : third step refused under a 2-step license")
# Mode B on the device: the calldata a wallet sends to ZenoLlullVerifier.sol
# (executed in the EVM tests; here the same calls through the bindings).
ptau = (ROOT / "crates/evm-verifier/fixtures/pot7_test.ptau").read_bytes()
onchain = zenollull.OnChainProver(LICENSE, r1cs, ptau, ["3"])
assert onchain.vk().startswith("0x") and len(onchain.vk()) == 66
assert len(onchain.open_session_calldata()) == 4 + 32 * 4
session = "0x" + "11" * 32
for wtns in witnesses:
    onchain.prove_step(wtns)
assert onchain.pending_steps() == 3
batch = onchain.take_calldata(session)
assert batch[4:36] == bytes.fromhex("11" * 32)
final = onchain.finalize(session)
assert onchain.steps() == 3 and onchain.state() == ["130308420719099"]
expect_error(zenollull.ZenoError.InvalidInput, lambda: onchain.take_calldata("0x12"))
print(f"mode B   : 3 steps, batch {len(batch)} bytes, finalizeUniversal {len(final)} bytes of calldata")
print("OK")
