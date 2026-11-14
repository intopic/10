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
// The production tool: Circom `.r1cs` / `.wtns` in, calldata out.
const ZENO_EVM = process.env.ZENO_EVM ?? path.join(ROOT, "target/release/zeno-evm");
const CIRCOM = path.join(ROOT, "crates/sdk-bindings/fixtures");
const MAX_STEP_GAS = 300_000n;
const FEE = 1_000_000_000_000n; // stepFee: 1e-6 ether per folded step
const DECISION_FEE = 5n * FEE; // decisionFee: per finalization
const MAX_FEE = 10n * FEE; // the permanent cap of both fees
const STEPS = 5;

function compile() {
  const read = (name) => ({ content: fs.readFileSync(path.join(__dirname, "..", name), "utf8") });
  const input = {
    language: "Solidity",
    sources: {
      "ZenoLlullVerifier.sol": read("ZenoLlullVerifier.sol"),
      "lib/ZenoBn254.sol": read("lib/ZenoBn254.sol"),
      "lib/ZenoFees.sol": read("lib/ZenoFees.sol"),
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
    production: out.contracts["ZenoLlullVerifier.sol"].ZenoLlullVerifier,
    decider: out.contracts["ZenoUniversalDecider.sol"].ZenoUniversalDecider,
  };
}

const word = (v) => v.toString(16).padStart(64, "0");
const fixture = (args) =>
  JSON.parse(execFileSync(FIXTURE_BIN, args, { encoding: "utf8", maxBuffer: 1 << 28 }));
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

  // The contract has no Groth16 decider (removed) and no way to replace
  // the universal decider.
  for (const name of ["finalizeWithProof", "registerDevDeciderKey", "setUniversalDecider", "deciderKeyHash"]) {
    const found = Object.keys(compiled.production.evm.methodIdentifiers).filter((m) => m.startsWith(name + "("));
    assert.deepEqual(found, [], `${name} must not be in the production contract`);
  }

  // The universal decider is deployed first and fixed in the constructor.
  const deployDecider = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + compiled.decider.evm.bytecode.object),
    gasLimit: 10_000_000n,
  });
  assert.equal(deployDecider.execResult.exceptionError, undefined, "decider deployment failed");
  console.log(`universal decider    : ${deployDecider.execResult.executionGasUsed} gas to deploy`);
  const deciderAddress = deployDecider.createdAddress;
  // An address without code is refused.
  const noDecider = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + contract.evm.bytecode.object + word(FEE) + word(DECISION_FEE) + word(MAX_FEE) + word(0xdeadn)),
    gasLimit: 10_000_000n,
  });
  assert.notEqual(noDecider.execResult.exceptionError, undefined, "a decider without code was accepted");

  const deploy = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + contract.evm.bytecode.object + word(FEE) + word(DECISION_FEE) + word(MAX_FEE) + word(BigInt(deciderAddress.toString()))),
    gasLimit: 10_000_000n,
  });
  assert.equal(deploy.execResult.exceptionError, undefined, "deployment failed");
  // A fee above its cap is refused at deployment.
  const overCap = await evm.runCall({
    caller: owner,
    data: hexToBytes("0x" + contract.evm.bytecode.object + word(FEE) + word(MAX_FEE + 1n) + word(MAX_FEE) + word(BigInt(deciderAddress.toString()))),
    gasLimit: 10_000_000n,
  });
  assert.notEqual(overCap.execResult.exceptionError, undefined, "a fee above the cap was accepted");
  const to = deploy.createdAddress;
  console.log(`deployment           : ${deploy.execResult.executionGasUsed} gas`);

  // Finalizations pay one fee: attached automatically unless a value is
  // given, and counted when they succeed.
  const finalizers = new Set(
    Object.entries(sel)
      .filter(([sig]) => /^(finalize|finalizeUniversal)\(/.test(sig))
      .map(([, id]) => id)
  );
  let paidFinalizations = 0;
  const call = async (caller, dataHex, value) => {
    const data = hexToBytes(dataHex);
    const finalizing = finalizers.has(dataHex.slice(2, 10));
    value ??= finalizing ? DECISION_FEE : 0n;
    const res = await evm.runCall({ caller, to, data, value, gasLimit: 5_000_000n });
    if (finalizing && res.execResult.exceptionError === undefined) paidFinalizations += 1;
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
  // A finalization pays exactly one fee.
  await revertsWith(call(prover, fx.finalize.calldata, 0n), "WrongFee()");
  await revertsWith(call(prover, fx.finalize.calldata, FEE), "WrongFee()");
  await revertsWith(call(prover, fx.finalize.calldata, DECISION_FEE + 1n), "WrongFee()");
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

  const flip = (hex, byteOffset) => {
    const i = 2 + 2 * byteOffset;
    const b = (parseInt(hex.slice(i, i + 2), 16) ^ 1).toString(16).padStart(2, "0");
    return hex.slice(0, i) + b + hex.slice(i + 2);
  };

  let extraStepsEarly = 0;
  // --- Universal decider: no per-circuit keys ----------------------------------
  {
    const got = await call(stranger, "0x" + sel["universalDecider()"]);
    assert.equal(BigInt(got.ret), BigInt(deciderAddress.toString()), "the decider fixed at deployment");
  }

  const preU = fixture(["--steps", "1", "--mode", "universal"]);
  const openedU = await call(prover, preU.open);
  assert.ok(openedU.ok);
  const fu = fixture(["--session", openedU.ret, "--steps", String(STEPS), "--mode", "universal"]);
  for (const step of fu.steps) {
    assert.ok((await call(prover, step.calldata, FEE)).ok);
  }
  const fin2 = fu.finalizeUniversal;
  // Anyone may publish a circuit key; nothing depends on it.
  const announced = await call(stranger, fu.announce);
  assert.ok(announced.ok);
  assert.equal(announced.ret, fu.vk, "circuit id is the hash of the key");

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

  // Regression (public-input count): the decider itself, called directly,
  // accepts the proof for the accumulator the contract will hold, and
  // refuses the same call with one more public input — a value no
  // constraint of the circuit touches — as malformed.
  {
    const dsel = compiled.decider.evm.methodIdentifiers["verify(bytes32,uint256[],uint256[],uint256[])"];
    const body = fin2.calldata.slice(2);
    const words = (start, n) => body.slice(2 * start, 2 * (start + 32 * n));
    const key = words(uKeyStart, fin2.keyWords);
    const proof = words(uProofStart, fin2.proofWords);
    assert.equal(fin2.keyWords, 24);
    assert.equal(BigInt("0x" + key.slice(-64)), 2n, "the key's last word is the number of public inputs");
    const direct = async (acc) => {
      const accWords = acc.map((w) => w.slice(2)).join("");
      const o1 = 4 * 32;
      const o2 = o1 + 32 * (1 + fin2.keyWords);
      const o3 = o2 + 32 * (1 + acc.length);
      const data =
        "0x" + dsel + fu.vk.slice(2) + word(BigInt(o1)) + word(BigInt(o2)) + word(BigInt(o3)) +
        word(BigInt(fin2.keyWords)) + key + word(BigInt(acc.length)) + accWords +
        word(BigInt(fin2.proofWords)) + proof;
      const res = await evm.runCall({ caller: stranger, to: deciderAddress, data: hexToBytes(data), gasLimit: 5_000_000n });
      return { ok: res.execResult.exceptionError === undefined, ret: bytesToHex(res.execResult.returnValue) };
    };
    const honest = await direct(fin2.accumulator);
    assert.ok(honest.ok && BigInt(honest.ret) === 1n, "the decider accepts the honest accumulator");
    const { keccak256 } = require("ethereum-cryptography/keccak.js");
    const malformed = bytesToHex(keccak256(Buffer.from("MalformedInput()"))).slice(0, 10);
    for (const acc of [[...fin2.accumulator, "0x" + word(0n)], [...fin2.accumulator, "0x" + word(7n)], fin2.accumulator.slice(0, -1)]) {
      const res = await direct(acc);
      assert.equal(res.ok, false, "an accumulator with another number of public inputs was accepted");
      assert.equal(res.ret.slice(0, 10), malformed, "refused as malformed input");
    }
  }

  await revertsWith(call(prover, fin2.calldata, 0n), "WrongFee()");
  const decidedU = await call(prover, fin2.calldata);
  assert.ok(decidedU.ok, "finalizeUniversal reverted");
  console.log(`finalizeUniversal    : ${decidedU.gas} gas (no circuit-specific setup)`);
  console.log(`universal proof      : ${fin2.proofBytes} bytes`);
  const finalU = await readAccumulator(fu.getAccumulator);
  assert.deepEqual(finalU.acc, fin2.accumulator);
  assert.equal(finalU.decided, true);
  assert.equal(finalU.steps, STEPS);
  await revertsWith(call(prover, fin2.calldata), "SessionClosed()");

  // A session opened for another circuit cannot be decided with this key:
  // the key of the 128-round circuit against a session of the 8-round one.
  {
    const other = fixture(["--steps", "1", "--mode", "universal", "--rounds", "128"]);
    const openedX = await call(prover, preU.open);
    const fxX = fixture(["--session", openedX.ret, "--steps", "1", "--mode", "universal"]);
    assert.ok((await call(prover, fxX.steps[0].calldata, FEE)).ok);
    const otherForX = fixture(["--session", openedX.ret, "--steps", "1", "--mode", "universal", "--rounds", "128"]);
    assert.notEqual(other.vk, fxX.vk);
    await revertsWith(call(prover, otherForX.finalizeUniversal.calldata), "UnknownDeciderKey()");
    assert.ok((await call(prover, fxX.finalizeUniversal.calldata)).ok);
    extraStepsEarly += 1;
  }

  // --- Universal decider: cost as the circuit grows ----------------------------
  let extraSteps = extraStepsEarly;
  // With ZENO_PTAU (a public Powers-of-Tau file with at least 2^18 powers)
  // the 2^16-constraint circuit is measured on the real ceremony string.
  const sizes = [[128, []], [2048, []]];
  if (process.env.ZENO_PTAU) sizes.push([32768, ["--ptau", process.env.ZENO_PTAU]]);
  for (const [rounds, extra] of sizes) {
    const args = ["--steps", "1", "--mode", "universal", "--rounds", String(rounds), ...extra];
    const pre = fixture(args);
    const opened = await call(prover, pre.open);
    assert.ok(opened.ok);
    const fx2 = fixture(["--session", opened.ret, ...args]);
    assert.ok((await call(prover, fx2.steps[0].calldata, FEE)).ok);
    extraSteps += 1;
    const res = await call(prover, fx2.finalizeUniversal.calldata);
    assert.ok(res.ok, `finalizeUniversal reverted for ${2 * rounds} constraints`);
    console.log(
      `finalizeUniversal    : ${res.gas} gas, proof ${fx2.finalizeUniversal.proofBytes} bytes (${2 * rounds} constraints${extra.length ? ", public .ptau" : ""})`
    );
    assert.equal((await readAccumulator(fx2.getAccumulator)).decided, true);
  }

  // --- Many steps in one transaction ---------------------------------------------
  const BATCH = 100;
  {
    const openedB2 = await call(prover, pre.open);
    assert.ok(openedB2.ok);
    const fbatch = fixture(["--session", openedB2.ret, "--steps", String(BATCH)]);
    await revertsWith(call(prover, fbatch.batch, FEE), "WrongFee()");
    await revertsWith(call(stranger, fbatch.batch, FEE * BigInt(BATCH)), "NotSessionProver()");
    const res = await call(prover, fbatch.batch, FEE * BigInt(BATCH));
    assert.ok(res.ok, "batch fold reverted");
    const after = await readAccumulator(fbatch.getAccumulator);
    // The batch reaches exactly the accumulator of folding the steps one by one.
    assert.deepEqual(after.acc, fbatch.steps[BATCH - 1].accumulator);
    assert.deepEqual(after.state, [fbatch.steps[BATCH - 1].state]);
    assert.equal(after.steps, BATCH);
    console.log(
      `verifyFoldedProofBatch: ${res.gas} gas for ${BATCH} steps (${res.gas / BigInt(BATCH)} gas / step)`
    );
    // Replaying the batch does not continue from the current state.
    await revertsWith(call(prover, fbatch.batch, FEE * BigInt(BATCH)), "StateMismatch()");
    assert.ok((await call(prover, fbatch.finalize.calldata)).ok);
    assert.equal(fbatch.deciderAccepts, true);
    extraSteps += BATCH;
  }

  // --- Circom -> EVM (mode B): a real Circom circuit, end to end -------------------
  // Witnesses come from Circom's own witness generator; `zeno-evm` turns the
  // `.r1cs` and `.wtns` files into calldata; the contract folds every step
  // and decides the result with the universal decider.
  {
    const CIRCOM_STEPS = 4;
    const os = require("node:os");
    const witnessCalculator = require(path.join(CIRCOM, "witness_calculator.js"));
    const calc = await witnessCalculator(fs.readFileSync(path.join(CIRCOM, "step.wasm")));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zeno-circom-"));
    const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const wtns = [];
    let z = 3n;
    for (let i = 0; i < CIRCOM_STEPS; i++) {
      const secret = BigInt(11 + i);
      const file = path.join(dir, `step${i}.wtns`);
      fs.writeFileSync(file, await calc.calculateWTNSBin({ step_in: [z.toString()], secret: secret.toString() }, 0));
      wtns.push(file);
      z = (z * z * z + z + secret) % P;
    }
    const ptau = process.env.ZENO_PTAU ?? path.join(ROOT, "crates/evm-verifier/fixtures/pot7_test.ptau");
    const tool = (args) =>
      JSON.parse(execFileSync(ZENO_EVM, args, { encoding: "utf8", maxBuffer: 1 << 28 }));
    const r1cs = path.join(CIRCOM, "step.r1cs");
    const key = tool(["key", "--r1cs", r1cs, "--ptau", ptau, "--z0", "3"]);
    const openedC = await call(prover, key.open);
    assert.ok(openedC.ok, "openSession for the Circom circuit failed");
    const out = tool(["universal", "--r1cs", r1cs, "--ptau", ptau, "--z0", "3", "--session", openedC.ret, "--wtns", ...wtns]);
    assert.equal(out.vk, key.vk);
    assert.deepEqual(out.zi, [z.toString()]);
    const folded = await call(prover, out.verifyFoldedProofBatch, FEE * BigInt(CIRCOM_STEPS));
    assert.ok(folded.ok, "verifyFoldedProofBatch of the Circom steps reverted");
    const decidedC = await call(prover, out.finalizeUniversal);
    assert.ok(decidedC.ok, "finalizeUniversal of the Circom circuit reverted");
    const get = "0x" + sel["getAccumulator(bytes32)"] + openedC.ret.slice(2);
    const after = await readAccumulator(get);
    assert.equal(after.decided, true);
    assert.equal(after.steps, CIRCOM_STEPS);
    assert.deepEqual(after.state.map(BigInt), [z]);
    // A witness that does not continue from the state is refused by the tool.
    assert.throws(() =>
      execFileSync(ZENO_EVM, ["universal", "--r1cs", r1cs, "--ptau", ptau, "--z0", "3", "--session", openedC.ret, "--wtns", wtns[1]], { stdio: "pipe" })
    );
    fs.rmSync(dir, { recursive: true });
    extraSteps += CIRCOM_STEPS;
    console.log(
      `Circom -> EVM (B)    : ${CIRCOM_STEPS} steps of step.circom, batch ${folded.gas} gas, finalizeUniversal ${decidedC.gas} gas, proof ${out.proofBytes} bytes`
    );
  }

  // --- Protocol fee -----------------------------------------------------------
  const balance = async (a) => (await evm.stateManager.getAccount(a))?.balance ?? 0n;
  const paid = FEE * BigInt(2 * STEPS + extraSteps) + DECISION_FEE * BigInt(paidFinalizations);
  assert.equal(await balance(to), paid);
  // The owner sets both fees, each never above the cap; nobody else can.
  const setFees = (step, decision) => "0x" + sel["setFees(uint256,uint256)"] + word(step) + word(decision);
  await revertsWith(call(owner, setFees(MAX_FEE + 1n, 0n)), "FeeAboveCap()");
  await revertsWith(call(owner, setFees(0n, MAX_FEE + 1n)), "FeeAboveCap()");
  assert.ok((await call(owner, setFees(0n, MAX_FEE))).ok);
  assert.equal(BigInt((await call(stranger, "0x" + sel["stepFee()"])).ret), 0n);
  assert.equal(BigInt((await call(stranger, "0x" + sel["decisionFee()"])).ret), MAX_FEE);
  assert.equal(BigInt((await call(stranger, "0x" + sel["maxFee()"])).ret), MAX_FEE);
  assert.ok((await call(owner, setFees(FEE, DECISION_FEE))).ok);
  const withdraw = "0x" + sel["withdrawFees(address)"] + word(BigInt(owner.toString()));
  await revertsWith(call(stranger, withdraw), "NotOwner()");
  await revertsWith(call(stranger, setFees(0n, 0n)), "NotOwner()");
  const before = await balance(owner);
  assert.ok((await call(owner, withdraw)).ok);
  assert.equal(await balance(to), 0n);
  assert.equal((await balance(owner)) - before, paid);
  console.log(`protocol fees        : ${2 * STEPS + extraSteps} steps × stepFee + ${paidFinalizations} decisions × decisionFee, cap ${MAX_FEE} wei enforced`);
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
