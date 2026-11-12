// Executes ZenoLlullVerifier.sol in an in-process EVM (with the real BN254
// precompiles) against calldata produced by the Rust prover library, and
// checks that the contract reaches exactly the accumulator the prover
// expects, within the gas budget of the specification.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const solc = require("solc");
const { EVM } = require("@ethereumjs/evm");
const { Common, Chain, Hardfork } = require("@ethereumjs/common");
const { Address, Account, hexToBytes, bytesToHex } = require("@ethereumjs/util");

const ROOT = path.join(__dirname, "../..");
const FIXTURE_BIN = process.env.ZENO_EVM_FIXTURE ?? path.join(ROOT, "target/release/zeno-evm-fixture");
const MAX_STEP_GAS = 300_000n;
const FEE = 1_000_000_000_000n; // 1e-6 ether per folded step
const STEPS = 5;

function compile() {
  const read = (name) => ({ content: fs.readFileSync(path.join(__dirname, "..", name), "utf8") });
  const input = {
    language: "Solidity",
    sources: {
      "ZenoLlullVerifier.sol": read("ZenoLlullVerifier.sol"),
      "ZenoUniversalDecider.sol": read("ZenoUniversalDecider.sol"),
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      evmVersion: "cancun",
      outputSelection: { "*": { "*": ["evm.bytecode.object", "evm.methodIdentifiers"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  const warnings = (out.errors ?? []).filter((e) => e.severity === "warning");
  assert.equal(warnings.length, 0, warnings.map((e) => e.formattedMessage).join("\n"));
  return {
    verifier: out.contracts["ZenoLlullVerifier.sol"].ZenoLlullVerifier,
    decider: out.contracts["ZenoUniversalDecider.sol"].ZenoUniversalDecider,
  };
}

const word = (v) => v.toString(16).padStart(64, "0");
const fixture = (args) => JSON.parse(execFileSync(FIXTURE_BIN, args, { encoding: "utf8" }));
// Gas a transaction pays on top of execution: base cost plus calldata.
const intrinsicGas = (data) =>
  21000n + data.reduce((acc, b) => acc + (b === 0 ? 4n : 16n), 0n);

(async () => {
  const compiled = compile();
  const contract = compiled.verifier;
  const sel = contract.evm.methodIdentifiers;
  const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Cancun });
  const evm = await EVM.create({ common });

  const owner = Address.fromString("0x00000000000000000000000000000000000000a1");
  const prover = Address.fromString("0x00000000000000000000000000000000000000b2");
  const stranger = Address.fromString("0x00000000000000000000000000000000000000c3");
  for (const a of [owner, prover, stranger]) {
    await evm.stateManager.putAccount(a, new Account(0n, 10n ** 18n));
  }

  const deploy = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + contract.evm.bytecode.object + word(FEE)),
    gasLimit: 10_000_000n,
  });
  assert.equal(deploy.execResult.exceptionError, undefined, "deployment failed");
  const to = deploy.createdAddress;
  console.log(`deployment           : ${deploy.execResult.executionGasUsed} gas`);

  const call = async (caller, dataHex, value = 0n) => {
    const data = hexToBytes(dataHex);
    const res = await evm.runCall({ caller, to, data, value, gasLimit: 5_000_000n });
    return {
      ok: res.execResult.exceptionError === undefined,
      ret: bytesToHex(res.execResult.returnValue),
      gas: res.execResult.executionGasUsed + intrinsicGas(data),
    };
  };
  const revertsWith = async (promise, errorSignature) => {
    const res = await promise;
    assert.equal(res.ok, false, `expected revert ${errorSignature}`);
    // Custom errors are identified by their 4-byte selector; compute it via
    // the contract's own ABI-free check: compare against keccak of signature.
    const { keccak256 } = require("ethereum-cryptography/keccak.js");
    const expected = bytesToHex(keccak256(Buffer.from(errorSignature))).slice(0, 10);
    assert.equal(res.ret.slice(0, 10), expected, `expected ${errorSignature}`);
  };

  // --- Open a session ---------------------------------------------------
  const pre = fixture(["--steps", "1"]);
  const opened = await call(prover, pre.open);
  assert.ok(opened.ok, "openSession failed");
  const sessionId = opened.ret;
  console.log(`openSession          : ${opened.gas} gas`);
  const fx = fixture(["--session", sessionId, "--steps", String(STEPS)]);
  assert.equal(fx.vk, pre.vk);

  const readAccumulator = async (getCalldata = fx.getAccumulator) => {
    const res = await call(stranger, getCalldata);
    assert.ok(res.ok);
    const words = res.ret.slice(2).match(/.{64}/g);
    const at = (i) => BigInt("0x" + words[i]);
    const array = (offsetWord) => {
      const start = Number(at(offsetWord)) / 32;
      const len = Number(at(start));
      return words.slice(start + 1, start + 1 + len).map((w) => "0x" + w);
    };
    return {
      acc: [...words.slice(0, 5).map((w) => "0x" + w), ...array(5)],
      state: array(6),
      steps: Number(at(7)),
      finalized: at(8) === 1n,
      vk: "0x" + words[9],
      decided: at(10) === 1n,
    };
  };

  // --- Access control and fee ---------------------------------------------
  const first = fx.steps[0].calldata;
  await revertsWith(call(prover, first, 0n), "WrongFee()");
  await revertsWith(call(prover, first, FEE + 1n), "WrongFee()");
  await revertsWith(call(stranger, first, FEE), "NotSessionProver()");
  // A point that is not on the curve is rejected by the precompile.
  const offCurve = first.slice(0, 2 + 2 * (4 + 32 * 4 + 64) - 2) + "07" + first.slice(2 + 2 * (4 + 32 * 4 + 64));
  await revertsWith(call(prover, offCurve, FEE), "InvalidPoint()");
  assert.equal((await readAccumulator()).steps, 0);

  // --- Fold every step ------------------------------------------------------
  let maxGas = 0n;
  for (const [i, step] of fx.steps.entries()) {
    const res = await call(prover, step.calldata, FEE);
    assert.ok(res.ok, `step ${i} reverted`);
    assert.equal(res.ret, sessionId);
    const onchain = await readAccumulator();
    assert.deepEqual(onchain.acc, step.accumulator, `accumulator mismatch after step ${i}`);
    assert.deepEqual(onchain.state, [step.state]);
    assert.equal(onchain.steps, i + 1);
    assert.ok(res.gas < MAX_STEP_GAS, `step ${i} used ${res.gas} gas`);
    if (res.gas > maxGas) maxGas = res.gas;
    if (i === 0 || i === fx.steps.length - 1) {
      console.log(`verifyFoldedProof #${i + 1} : ${res.gas} gas (incl. 21000 base + calldata)`);
    }
  }
  console.log(`max step gas         : ${maxGas} (limit ${MAX_STEP_GAS})`);
  // Replaying an old step does not continue from the current state.
  await revertsWith(call(prover, fx.steps[0].calldata, FEE), "StateMismatch()");

  // --- Finalize ---------------------------------------------------------------
  await revertsWith(call(stranger, fx.finalize.calldata), "NotSessionProver()");
  const fin = await call(prover, fx.finalize.calldata);
  assert.ok(fin.ok, "finalize reverted");
  console.log(`finalize             : ${fin.gas} gas`);
  const final = await readAccumulator();
  assert.deepEqual(final.acc, fx.finalize.accumulator, "final accumulator mismatch");
  assert.equal(final.finalized, true);
  assert.equal(final.vk, fx.vk);
  assert.equal(final.steps, STEPS);
  await revertsWith(call(prover, fx.steps[0].calldata, FEE), "SessionClosed()");
  await revertsWith(call(prover, fx.finalize.calldata), "SessionClosed()");

  // The off-chain decider accepts exactly the accumulator now on-chain.
  assert.equal(fx.deciderAccepts, true);
  assert.equal(fx.deciderRejectsOther, true);

  assert.equal(final.decided, false, "transparent mode is decided off-chain only");

  // --- Mode B: on-chain decider (KZG openings + Groth16) -----------------------
  const preB = fixture(["--steps", "1", "--mode", "onchain"]);
  const openedB = await call(prover, preB.open);
  assert.ok(openedB.ok);
  const fb = fixture(["--session", openedB.ret, "--steps", String(STEPS), "--mode", "onchain"]);
  for (const step of fb.steps) {
    assert.ok((await call(prover, step.calldata, FEE)).ok);
  }
  const fwp = fb.finalizeWithProof.calldata;
  // No decider key registered for this circuit yet.
  await revertsWith(call(prover, fwp), "UnknownDeciderKey()");
  await revertsWith(call(stranger, fb.register), "NotOwner()");
  assert.ok((await call(owner, fb.register)).ok);
  await revertsWith(call(owner, fb.register), "CircuitAlreadyRegistered()");

  // Forgeries: flip one bit in each of the 17 proof words and in the key.
  const flip = (hex, byteOffset) => {
    const i = 2 + 2 * byteOffset;
    const b = (parseInt(hex.slice(i, i + 2), 16) ^ 1).toString(16).padStart(2, "0");
    return hex.slice(0, i) + b + hex.slice(i + 2);
  };
  const proofStart = 4 + 64; // selector, sessionId, offset of maskProof
  for (let w = 0; w < 17; w++) {
    const res = await call(prover, flip(fwp, proofStart + 32 * w + 31));
    assert.equal(res.ok, false, `forged proof word ${w} was accepted`);
  }
  const keyStart = (fwp.length - 2) / 2 - 32;
  await revertsWith(call(prover, flip(fwp, keyStart + 31)), "UnknownDeciderKey()");
  assert.equal((await readAccumulator(fb.getAccumulator)).finalized, false);

  const decided = await call(prover, fwp);
  assert.ok(decided.ok, "finalizeWithProof reverted");
  console.log(`finalizeWithProof    : ${decided.gas} gas (mask fold + 2 KZG openings + Groth16)`);
  console.log(`on-chain proof       : ${fb.finalizeWithProof.proofBytes} bytes`);
  const finalB = await readAccumulator(fb.getAccumulator);
  assert.deepEqual(finalB.acc, fb.finalizeWithProof.accumulator);
  assert.equal(finalB.finalized, true);
  assert.equal(finalB.decided, true);
  assert.equal(finalB.steps, STEPS);
  assert.deepEqual(finalB.state, [fb.steps[STEPS - 1].state]);
  await revertsWith(call(prover, fwp), "SessionClosed()");
  assert.ok(fb.finalizeWithProof.proofBytes < 4096);

  // --- Universal decider: no per-circuit keys ----------------------------------
  const deployDecider = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + compiled.decider.evm.bytecode.object),
    gasLimit: 10_000_000n,
  });
  assert.equal(deployDecider.execResult.exceptionError, undefined, "decider deployment failed");
  console.log(`universal decider    : ${deployDecider.execResult.executionGasUsed} gas to deploy`);
  const setDecider =
    "0x" + sel["setUniversalDecider(address)"] + word(BigInt(deployDecider.createdAddress.toString()));
  await revertsWith(call(stranger, setDecider), "NotOwner()");
  assert.ok((await call(owner, setDecider)).ok);

  const preU = fixture(["--steps", "1", "--mode", "universal"]);
  const openedU = await call(prover, preU.open);
  assert.ok(openedU.ok);
  const fu = fixture(["--session", openedU.ret, "--steps", String(STEPS), "--mode", "universal"]);
  for (const step of fu.steps) {
    assert.ok((await call(prover, step.calldata, FEE)).ok);
  }
  const fin2 = fu.finalizeUniversal;
  await revertsWith(call(prover, fin2.calldata), "UnknownDeciderKey()");
  assert.ok((await call(owner, fu.register)).ok);

  // Forgeries: flip one bit in every word of the proof and of the key.
  const total = (fin2.calldata.length - 2) / 2;
  const uProofStart = total - 32 * fin2.proofWords;
  const uKeyStart = uProofStart - 32 - 32 * fin2.keyWords;
  for (let w = 0; w < fin2.proofWords; w++) {
    const res = await call(prover, flip(fin2.calldata, uProofStart + 32 * w + 31));
    assert.equal(res.ok, false, `forged universal proof word ${w} was accepted`);
  }
  for (let w = 0; w < fin2.keyWords; w++) {
    await revertsWith(call(prover, flip(fin2.calldata, uKeyStart + 32 * w + 31)), "UnknownDeciderKey()");
  }
  // A truncated proof is malformed, not accepted.
  assert.equal((await call(prover, fin2.calldata.slice(0, -64))).ok, false);
  assert.equal((await readAccumulator(fu.getAccumulator)).finalized, false);

  const decidedU = await call(prover, fin2.calldata);
  assert.ok(decidedU.ok, "finalizeUniversal reverted");
  console.log(`finalizeUniversal    : ${decidedU.gas} gas (no circuit-specific setup)`);
  console.log(`universal proof      : ${fin2.proofBytes} bytes`);
  const finalU = await readAccumulator(fu.getAccumulator);
  assert.deepEqual(finalU.acc, fin2.accumulator);
  assert.equal(finalU.decided, true);
  assert.equal(finalU.steps, STEPS);
  await revertsWith(call(prover, fin2.calldata), "SessionClosed()");

  // --- Protocol fee -----------------------------------------------------------
  const balance = async (a) => (await evm.stateManager.getAccount(a))?.balance ?? 0n;
  assert.equal(await balance(to), FEE * BigInt(3 * STEPS));
  const withdraw = "0x" + sel["withdrawFees(address)"] + word(BigInt(owner.toString()));
  await revertsWith(call(stranger, withdraw), "NotOwner()");
  await revertsWith(call(stranger, "0x" + sel["setProtocolFee(uint256)"] + word(0n)), "NotOwner()");
  const before = await balance(owner);
  assert.ok((await call(owner, withdraw)).ok);
  assert.equal(await balance(to), 0n);
  assert.equal((await balance(owner)) - before, FEE * BigInt(3 * STEPS));
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
