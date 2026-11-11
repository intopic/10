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

(async () => {
  const r1cs = fs.readFileSync(path.join(fixtures, "step.r1cs"));
  const calc = await witnessCalculator(fs.readFileSync(path.join(fixtures, "step.wasm")));

  let t = performance.now();
  const prover = new sdk.ZenoLlullProver(r1cs, ["3"]);
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

  // Any bit flip invalidates the proof.
  for (const offset of [8, proof.length >> 1, proof.length - 1]) {
    const bad = Uint8Array.from(proof);
    bad[offset] ^= 1;
    assert.throws(() => verifier.verify(bad));
  }
  assert.throws(() => new sdk.ZenoLlullProver(r1cs.subarray(0, 100), ["3"]), /malformed/);
  assert.throws(() => new sdk.ZenoLlullProver(r1cs, ["not-a-number"]), /invalid field element/);

  assert.equal(verifier.verifications, 4);

  // License keys: a syntactically valid key signed by nobody is refused.
  assert.throws(() => sdk.verifyLicense("zl1.YQ.Yg", "00".repeat(32), Date.now() / 1000));
  assert.throws(() => sdk.verifyLicense("nonsense", "00".repeat(32), 0), /malformed/);
  if (process.env.ZENO_TEST_LICENSE) {
    const lic = sdk.verifyLicense(process.env.ZENO_TEST_LICENSE, process.env.ZENO_LICENSE_PUBLIC_KEY, Date.now() / 1000);
    assert.equal(lic.customer, "ci");
    console.log(`license          : ${lic.customer} / ${lic.plan}`);
    assert.throws(() => sdk.verifyLicense(process.env.ZENO_TEST_LICENSE, process.env.ZENO_LICENSE_PUBLIC_KEY, 4e9), /expired/);
  }

  const peak = wasmMiB();
  console.log(`wasm memory      : ${memAfterFirst.toFixed(1)} MiB after step 1, ${peak.toFixed(1)} MiB at the end`);
  assert.ok(peak <= MAX_WASM_MIB, `wasm memory ${peak} MiB exceeds ${MAX_WASM_MIB} MiB`);
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
