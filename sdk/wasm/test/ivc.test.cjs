// End-to-end test of the WASM SDK in Node.js: witnesses come from Circom's
// own witness generator, every step is folded in WebAssembly, and the final
// zero-knowledge proof is checked by an independent verifier instance.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const sdk = require("../dist/node/sdk_bindings.js");
const fixtures = path.join(__dirname, "../../../crates/sdk-bindings/fixtures");
const witnessCalculator = require(path.join(fixtures, "witness_calculator.js"));

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const STEPS = Number(process.env.STEPS ?? 25);
const MAX_WASM_MIB = Number(process.env.MAX_WASM_MIB ?? 512);
const wasmMiB = () => sdk.wasmMemoryBytes() / (1024 * 1024);
// The prover runs only under a license. A package built without a vendor
// key (as in CI) checks against the public development key:
//   zeno-license issue --dev --customer ci --plan enterprise --days 1
const LICENSE = process.env.ZENO_TEST_LICENSE;
assert.ok(LICENSE, "set ZENO_TEST_LICENSE (see `zeno-license issue --dev`)");

(async () => {
  const r1cs = fs.readFileSync(path.join(fixtures, "step.r1cs"));
  const calc = await witnessCalculator(fs.readFileSync(path.join(fixtures, "step.wasm")));

  let t = performance.now();
  const prover = new sdk.ZenoLlullProver(LICENSE, r1cs, ["3"]);
  console.log(`setup            : ${(performance.now() - t).toFixed(0)} ms`);

  let z = 3n;
  let stateSize;
  let memAfterFirst;
  t = performance.now();
  for (let i = 0; i < STEPS; i++) {
    const secret = BigInt(7 + i);
    const wtns = await calc.calculateWTNSBin({ step_in: [z.toString()], secret: secret.toString() }, 0);
    prover.proveStep(wtns);
    z = (z * z * z + z + secret) % P;
    assert.deepEqual(prover.state, [z.toString()]);
    stateSize ??= prover.stateSize;
    assert.equal(prover.stateSize, stateSize, "prover state must not grow");
    memAfterFirst ??= wasmMiB();
  }
  console.log(`prover           : ${((performance.now() - t) / STEPS).toFixed(0)} ms / step (${STEPS} steps)`);
  assert.equal(prover.steps, STEPS);
  prover.verify();

  // A witness that does not continue from the current state is refused.
  const stale = await calc.calculateWTNSBin({ step_in: ["3"], secret: "7" }, 0);
  assert.throws(() => prover.proveStep(stale), /current IVC state/);
  assert.equal(prover.steps, STEPS);

  // Pause and resume: the saved state continues the same computation.
  t = performance.now();
  const saved = prover.saveState();
  const resumed = sdk.ZenoLlullProver.resume(LICENSE, r1cs, saved);
  console.log(`save + resume    : ${saved.length} bytes, ${(performance.now() - t).toFixed(0)} ms`);
  assert.equal(resumed.steps, STEPS);
  assert.deepEqual(resumed.state, prover.state);
  const corrupted = Uint8Array.from(saved);
  corrupted[corrupted.length - 40] ^= 1;
  assert.throws(() => sdk.ZenoLlullProver.resume(LICENSE, r1cs, corrupted));

  t = performance.now();
  const proof = prover.finalize();
  console.log(`finalize (ZK)    : ${(performance.now() - t).toFixed(0)} ms, proof ${proof.length} bytes`);
  assert.ok(proof.length <= 16 * 1024, `proof is ${proof.length} bytes`);

  const verifier = new sdk.ZenoLlullVerifier(r1cs);
  t = performance.now();
  const statement = verifier.verify(proof);
  console.log(`verify           : ${(performance.now() - t).toFixed(0)} ms`);
  assert.equal(statement.steps, STEPS);
  assert.deepEqual(statement.z0, ["3"]);
  assert.deepEqual(statement.zi, [z.toString()]);

  // The proof starts with its format: "ZLP" and version 1.
  assert.deepEqual([...proof.subarray(0, 4)], [0x5a, 0x4c, 0x50, 1]);
  const future = Uint8Array.from(proof);
  future[3] = 2;
  assert.throws(() => verifier.verify(future), /version 2 is not supported/);

  // Any bit flip invalidates the proof.
  for (const offset of [8, proof.length >> 1, proof.length - 1]) {
    const bad = Uint8Array.from(proof);
    bad[offset] ^= 1;
    assert.throws(() => verifier.verify(bad));
  }
  assert.throws(() => new sdk.ZenoLlullProver(LICENSE, r1cs.subarray(0, 100), ["3"]), /malformed/);
  assert.throws(() => new sdk.ZenoLlullProver(LICENSE, r1cs, ["not-a-number"]), /invalid field element/);

  assert.equal(verifier.verifications, 5);

  // License keys are checked against the vendor key compiled into the
  // package; the caller cannot supply a key or a clock of its own.
  assert.throws(() => sdk.verifyLicense("zl1.YQ.Yg"));
  assert.throws(() => sdk.verifyLicense("nonsense"), /malformed/);
  const lic = sdk.verifyLicense(LICENSE);
  assert.equal(lic.customer, "ci");
  console.log(`license          : ${lic.customer} / ${lic.plan}${lic.developmentBuild ? " (development build)" : ""}`);
  // No prover without a license, with a forged one, or with one signed by
  // somebody else (ZENO_FOREIGN_LICENSE: any key but the build's).
  assert.throws(() => new sdk.ZenoLlullProver("", r1cs, ["3"]), /license/);
  assert.throws(() => new sdk.ZenoLlullProver(LICENSE.slice(0, -4) + "AAAA", r1cs, ["3"]), /license/);
  if (process.env.ZENO_FOREIGN_LICENSE) {
    assert.throws(() => new sdk.ZenoLlullProver(process.env.ZENO_FOREIGN_LICENSE, r1cs, ["3"]), /signature/);
  }
  // A quota of two steps: the third step is refused.
  if (process.env.ZENO_QUOTA_LICENSE) {
    assert.equal(sdk.verifyLicense(process.env.ZENO_QUOTA_LICENSE).maxSteps, 2);
    const limited = new sdk.ZenoLlullProver(process.env.ZENO_QUOTA_LICENSE, r1cs, ["3"]);
    let s = 3n;
    for (let i = 0; i < 3; i++) {
      const w = await calc.calculateWTNSBin({ step_in: [s.toString()], secret: "7" }, 0);
      if (i < 2) limited.proveStep(w);
      else assert.throws(() => limited.proveStep(w), /quota/);
      s = (s * s * s + s + 7n) % P;
    }
    assert.equal(limited.steps, 2);
    console.log("license quota    : third step refused under a 2-step license");
  }

  const peak = wasmMiB();
  console.log(`wasm memory      : ${memAfterFirst.toFixed(1)} MiB after step 1, ${peak.toFixed(1)} MiB at the end`);
  assert.ok(peak <= MAX_WASM_MIB, `wasm memory ${peak} MiB exceeds ${MAX_WASM_MIB} MiB`);
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
