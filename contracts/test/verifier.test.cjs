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
  const source = fs.readFileSync(path.join(__dirname, "../ZenoLlullVerifier.sol"), "utf8");
  const input = {
    language: "Solidity",
    sources: { "ZenoLlullVerifier.sol": { content: source } },
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
  return out.contracts["ZenoLlullVerifier.sol"].ZenoLlullVerifier;
}

const word = (v) => v.toString(16).padStart(64, "0");
const fixture = (args) => JSON.parse(execFileSync(FIXTURE_BIN, args, { encoding: "utf8" }));
// Gas a transaction pays on top of execution: base cost plus calldata.
const intrinsicGas = (data) =>
  21000n + data.reduce((acc, b) => acc + (b === 0 ? 4n : 16n), 0n);

(async () => {
  const contract = compile();
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

  const readAccumulator = async () => {
    const res = await call(stranger, fx.getAccumulator);
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

  // --- Protocol fee -----------------------------------------------------------
  const balance = async (a) => (await evm.stateManager.getAccount(a))?.balance ?? 0n;
  assert.equal(await balance(to), FEE * BigInt(STEPS));
  const withdraw = "0x" + sel["withdrawFees(address)"] + word(BigInt(owner.toString()));
  await revertsWith(call(stranger, withdraw), "NotOwner()");
  await revertsWith(call(stranger, "0x" + sel["setProtocolFee(uint256)"] + word(0n)), "NotOwner()");
  const before = await balance(owner);
  assert.ok((await call(owner, withdraw)).ok);
  assert.equal(await balance(to), 0n);
  assert.equal((await balance(owner)) - before, FEE * BigInt(STEPS));
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
