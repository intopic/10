// Executes ZenoRecursiveVerifier.finalizeRecursive in an in-process EVM (with
// the real BN254 precompiles) against a proof produced by the Rust prover:
// one decision for a whole recursive (CycleFold) IVC run, and rejection of
// forged words in every part of the calldata.
//
// The fixture uses a 2^20-power reference string: ZENO_PTAU (a public
// Powers-of-Tau file), or a locally sampled test string without it.
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
const STEPS = 3;

function compile() {
  const read = (name) => ({ content: fs.readFileSync(path.join(__dirname, "..", name), "utf8") });
  const input = {
    language: "Solidity",
    sources: {
      "ZenoUniversalDecider.sol": read("ZenoUniversalDecider.sol"),
      "ZenoRecursiveVerifier.sol": read("ZenoRecursiveVerifier.sol"),
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      evmVersion: "cancun",
      outputSelection: { "*": { "*": ["evm.bytecode.object", "evm.methodIdentifiers", "evm.deployedBytecode.object"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  const warnings = (out.errors ?? []).filter((e) => e.severity === "warning");
  assert.equal(warnings.length, 0, warnings.map((e) => e.formattedMessage).join("\n"));
  return {
    decider: out.contracts["ZenoUniversalDecider.sol"].ZenoUniversalDecider,
    recursive: out.contracts["ZenoRecursiveVerifier.sol"].ZenoRecursiveVerifier,
  };
}

const word = (v) => v.toString(16).padStart(64, "0");
const intrinsicGas = (data) => 21000n + data.reduce((acc, b) => acc + (b === 0 ? 4n : 16n), 0n);

(async () => {
  const compiled = compile();
  const sel = compiled.recursive.evm.methodIdentifiers;
  const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Cancun });
  const evm = await EVM.create({ common });
  const deployer = Address.fromString("0x00000000000000000000000000000000000000a1");
  const prover = Address.fromString("0x00000000000000000000000000000000000000b2");
  for (const a of [deployer, prover]) await evm.stateManager.putAccount(a, new Account(0n, 10n ** 18n));

  const create = async (initHex, what) => {
    const res = await evm.runCall({ caller: deployer, data: hexToBytes(initHex), gasLimit: 30_000_000n });
    assert.equal(res.execResult.exceptionError, undefined, `${what} deployment failed`);
    return { address: res.createdAddress, gas: res.execResult.executionGasUsed };
  };

  console.log("generating the recursive proof (CycleFold IVC + two universal proofs) …");
  const args = ["--mode", "recursive", "--steps", String(STEPS)];
  if (process.env.ZENO_PTAU) args.push("--ptau", process.env.ZENO_PTAU);
  const t0 = Date.now();
  const fx = JSON.parse(execFileSync(FIXTURE_BIN, args, { encoding: "utf8", maxBuffer: 1 << 28 }));
  console.log(`prover               : ${((Date.now() - t0) / 1000).toFixed(1)} s for ${fx.steps} steps`);

  // The CycleFold matrices live in a data contract: initcode returning `0x00 ‖ data`.
  const code = fx.cfCode.slice(2);
  const codeLen = code.length / 2;
  assert.ok(codeLen <= 24576, "CycleFold data exceeds the contract size limit");
  const dataInit = "0x61" + codeLen.toString(16).padStart(4, "0") + "80600a3d393df3" + code;
  const data = await create(dataInit, "CycleFold data");
  const decider = await create("0x" + compiled.decider.evm.bytecode.object, "universal decider");
  const verifierInit =
    "0x" + compiled.recursive.evm.bytecode.object +
    word(BigInt(decider.address.toString())) + word(BigInt(data.address.toString()));
  const verifier = await create(verifierInit, "recursive verifier");
  console.log(`deployment           : ${verifier.gas} gas (verifier), ${data.gas} gas (CycleFold data, ${codeLen} bytes)`);

  const call = async (dataHex) => {
    const bytes = hexToBytes(dataHex);
    const res = await evm.runCall({ caller: prover, to: verifier.address, data: bytes, gasLimit: 30_000_000n });
    return {
      ok: res.execResult.exceptionError === undefined,
      gas: res.execResult.executionGasUsed + intrinsicGas(bytes),
      exec: res.execResult.executionGasUsed,
      ret: bytesToHex(res.execResult.returnValue),
    };
  };

  // ---- The honest decision --------------------------------------------------
  const res = await call(fx.calldata);
  assert.ok(res.ok, "finalizeRecursive reverted");
  assert.equal(res.ret, fx.systemId, "system id");
  const decided = await call("0x" + sel["decided(bytes32)"] + fx.decidedKey.slice(2));
  assert.equal(BigInt(decided.ret), 1n, "the claim is recorded as decided");
  const calldataBytes = (fx.calldata.length - 2) / 2;
  console.log(`finalizeRecursive    : ${res.gas} gas (${res.exec} execution, ${calldataBytes} bytes of calldata), ${fx.steps} IVC steps`);
  console.log(`proof                : ${fx.proofBytes} bytes; primary circuit ${fx.primaryConstraints} constraints, closing circuit ${fx.closingConstraints}`);

  // ---- Forgeries: one word in every part of the calldata --------------------
  const names = ["primary key", "closing key", "state", "CycleFold proof", "primary proof", "closing proof"];
  let forged = 0;
  for (let a = 0; a < 6; ++a) {
    const len = fx.lengths[a];
    const picks = a === 2 ? [0, 2, 3, 6, 9, 12, 15, 18, 21, len - 9, len - 1] : [0, Math.floor(len / 2), len - 1];
    for (const w of picks) {
      const at = 2 + 2 * (fx.starts[a] + 32 * w);
      const original = fx.calldata.slice(at, at + 64);
      const flipped = (BigInt("0x" + original) ^ 1n).toString(16).padStart(64, "0");
      const bad = fx.calldata.slice(0, at) + flipped + fx.calldata.slice(at + 64);
      const r = await call(bad);
      assert.equal(r.ok, false, `forged ${names[a]} word ${w} was accepted`);
      forged += 1;
    }
  }
  console.log(`forgeries            : ${forged} single-word changes, all rejected`);
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
