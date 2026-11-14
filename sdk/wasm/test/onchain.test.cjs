// Mode B from the WebAssembly SDK straight to the contract, with no API and
// no other tool: Circom's witness generator makes the witnesses, the SDK
// (as a wallet would run it) makes every calldata, and ZenoLlullVerifier.sol
// in an in-process EVM folds the steps and decides the result.
//
// Needs the contracts' dependencies: `npm ci --prefix contracts`.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "../../..");
const CONTRACTS = path.join(ROOT, "contracts");
const need = (name) => require(path.join(CONTRACTS, "node_modules", name));
const solc = need("solc");
const { EVM } = need("@ethereumjs/evm");
const { Common, Chain, Hardfork } = need("@ethereumjs/common");
const { Address, Account, hexToBytes, bytesToHex } = need("@ethereumjs/util");

const sdk = require("../dist/node/sdk_bindings.js");
const fixtures = path.join(ROOT, "crates/sdk-bindings/fixtures");
const witnessCalculator = require(path.join(fixtures, "witness_calculator.js"));
const LICENSE = process.env.ZENO_TEST_LICENSE;
assert.ok(LICENSE, "set ZENO_TEST_LICENSE (see `zeno-license issue --dev`)");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const FEE = 1_000_000_000_000n; // stepFee
const DECISION_FEE = 5n * FEE; // decisionFee
const word = (v) => v.toString(16).padStart(64, "0");

function compile() {
  const read = (name) => ({ content: fs.readFileSync(path.join(CONTRACTS, name), "utf8") });
  const sources = {};
  for (const f of ["ZenoLlullVerifier.sol", "ZenoUniversalDecider.sol", "lib/ZenoBn254.sol", "lib/ZenoFees.sol"]) {
    sources[f] = read(f);
  }
  const input = {
    language: "Solidity",
    sources,
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
  return {
    verifier: out.contracts["ZenoLlullVerifier.sol"].ZenoLlullVerifier,
    decider: out.contracts["ZenoUniversalDecider.sol"].ZenoUniversalDecider,
  };
}

(async () => {
  const compiled = compile();
  const sel = compiled.verifier.evm.methodIdentifiers;
  const evm = await EVM.create({ common: new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Cancun }) });
  const owner = Address.fromString("0x00000000000000000000000000000000000000a1");
  const wallet = Address.fromString("0x00000000000000000000000000000000000000b2");
  for (const a of [owner, wallet]) await evm.stateManager.putAccount(a, new Account(0n, 10n ** 18n));
  const create = async (hex) => {
    const res = await evm.runCall({ caller: owner, data: hexToBytes(hex), gasLimit: 30_000_000n });
    assert.equal(res.execResult.exceptionError, undefined, "deployment failed");
    return res.createdAddress;
  };
  const decider = await create("0x" + compiled.decider.evm.bytecode.object);
  const to = await create(
    "0x" + compiled.verifier.evm.bytecode.object + word(FEE) + word(DECISION_FEE) + word(10n * FEE) + word(BigInt(decider.toString()))
  );
  const send = async (data, value = 0n) => {
    if (typeof data === "string") data = hexToBytes(data);
    const res = await evm.runCall({ caller: wallet, to, data, value, gasLimit: 10_000_000n });
    assert.equal(res.execResult.exceptionError, undefined, "transaction reverted");
    return { ret: bytesToHex(res.execResult.returnValue), gas: res.execResult.executionGasUsed };
  };

  // ---- The wallet --------------------------------------------------------------
  const r1cs = fs.readFileSync(path.join(fixtures, "step.r1cs"));
  // A public ceremony file (here a small test ceremony); in production the
  // prefix this circuit needs, from `zeno-evm trim-ptau`.
  const ptau = fs.readFileSync(path.join(ROOT, "crates/evm-verifier/fixtures/pot7_test.ptau"));
  const calc = await witnessCalculator(fs.readFileSync(path.join(fixtures, "step.wasm")));

  let t = performance.now();
  const prover = new sdk.ZenoLlullOnChainProver(LICENSE, r1cs, ptau, ["3"]);
  console.log(`setup                : ${(performance.now() - t).toFixed(0)} ms, vk ${prover.vk}`);
  const sessionId = (await send(prover.openSessionCalldata())).ret;

  let z = 3n;
  const STEPS = 4;
  t = performance.now();
  for (let i = 0; i < STEPS; i++) {
    const secret = BigInt(5 + i);
    prover.proveStep(await calc.calculateWTNSBin({ step_in: [z.toString()], secret: secret.toString() }, 0));
    z = (z * z * z + z + secret) % P;
    // Steps go on-chain in two batches.
    if (i === 1 || i === STEPS - 1) {
      const n = BigInt(prover.pendingSteps);
      const r = await send(prover.takeCalldata(sessionId), FEE * n);
      console.log(`verifyFoldedProofBatch: ${n} steps, ${r.gas} gas`);
    }
  }
  console.log(`prover               : ${((performance.now() - t) / STEPS).toFixed(0)} ms / step (WASM)`);
  assert.deepEqual(prover.state, [z.toString()]);
  // A witness that does not continue from the state is refused locally.
  assert.throws(() => prover.proveStep(new Uint8Array(10)));

  t = performance.now();
  const fin = prover.finalize(sessionId);
  console.log(`finalize (ZK)        : ${(performance.now() - t).toFixed(0)} ms, ${fin.length} bytes of calldata`);
  const decided = await send(fin, DECISION_FEE);
  console.log(`finalizeUniversal    : ${decided.gas} gas`);

  // The contract holds the decision: state z_i after STEPS steps, decided.
  const acc = (await send("0x" + sel["getAccumulator(bytes32)"] + sessionId.slice(2))).ret.slice(2).match(/.{64}/g);
  const at = (i) => BigInt("0x" + acc[i]);
  const stateAt = Number(at(6)) / 32;
  assert.equal(at(stateAt + 1), z, "on-chain state");
  assert.equal(Number(at(7)), STEPS, "on-chain steps");
  assert.equal(at(10), 1n, "decided on-chain");
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
