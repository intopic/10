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
// The production tool: Circom `.r1cs` / `.wtns` in, calldata out.
const ZENO_EVM = process.env.ZENO_EVM ?? path.join(ROOT, "target/release/zeno-evm");
const CIRCOM = path.join(ROOT, "crates/sdk-bindings/fixtures");
const SERVER_BIN = process.env.ZENO_CLOUD_PROVER ?? path.join(ROOT, "target/release/zenollull-cloud-prover");
const LICENSE_BIN = path.join(ROOT, "target/release/zeno-license");
const STEPS = 3;
const FEE = 2_000_000_000_000n; // decisionFee: per finalizeRecursive
const MAX_FEE = 10n * FEE;

function compile() {
  const read = (name) => ({ content: fs.readFileSync(path.join(__dirname, "..", name), "utf8") });
  const input = {
    language: "Solidity",
    sources: {
      "ZenoBatchedDecider.sol": read("ZenoBatchedDecider.sol"),
      "lib/ZenoBn254.sol": read("lib/ZenoBn254.sol"),
      "lib/ZenoFees.sol": read("lib/ZenoFees.sol"),
      "ZenoRecursiveVerifier.sol": read("ZenoRecursiveVerifier.sol"),
      "ZenoCycleFoldShape.sol": read("ZenoCycleFoldShape.sol"),
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
    decider: out.contracts["ZenoBatchedDecider.sol"].ZenoBatchedDecider,
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

  console.log("generating the recursive proof (CycleFold IVC + one batched universal proof) …");
  const args = ["--mode", "recursive", "--steps", String(STEPS)];
  if (process.env.ZENO_PTAU) args.push("--ptau", process.env.ZENO_PTAU);
  const t0 = Date.now();
  const fx = JSON.parse(execFileSync(FIXTURE_BIN, args, { encoding: "utf8", maxBuffer: 1 << 28 }));
  console.log(`prover               : ${((Date.now() - t0) / 1000).toFixed(1)} s for ${fx.steps} steps`);

  // The CycleFold matrices are compiled into the verifier (ZenoCycleFoldShape).
  const decider = await create("0x" + compiled.decider.evm.bytecode.object, "batched decider");
  const verifierInit =
    "0x" + compiled.recursive.evm.bytecode.object + word(BigInt(decider.address.toString())) + word(FEE) + word(MAX_FEE);
  const verifier = await create(verifierInit, "recursive verifier");
  const runtime = compiled.recursive.evm.deployedBytecode.object.length / 2;
  assert.ok(runtime <= 24576, "the verifier exceeds the contract size limit");
  console.log(`deployment           : ${verifier.gas} gas (verifier, ${runtime} bytes), ${decider.gas} gas (batched decider)`);

  // finalizeRecursive pays one fee: attached unless another value is given.
  const finalizeSel = sel["finalizeRecursive(uint256[],uint256[],uint256[],uint256[],uint256[])"];
  const call = async (dataHex, value, caller = prover) => {
    const bytes = hexToBytes(dataHex);
    value ??= dataHex.slice(2, 10) === finalizeSel ? FEE : 0n;
    const res = await evm.runCall({ caller, to: verifier.address, data: bytes, value, gasLimit: 30_000_000n });
    return {
      ok: res.execResult.exceptionError === undefined,
      gas: res.execResult.executionGasUsed + intrinsicGas(bytes),
      exec: res.execResult.executionGasUsed,
      ret: bytesToHex(res.execResult.returnValue),
    };
  };

  // ---- Forgeries: one word in every part of the calldata, before the honest
  // claim is decided (a decided claim returns early, see below) ------------
  const names = ["primary key", "closing key", "state", "CycleFold proof", "decider proof"];
  let forged = 0;
  for (let a = 0; a < names.length; ++a) {
    const len = fx.lengths[a];
    const picks =
      a === 2 ? [0, 2, 3, 6, 9, 12, 15, 18, 21, len - 9, len - 1]
      : a === 4 ? [0, 3, 40, 100, 200, 300, 400, Math.floor(len / 2), len - 200, len - 7, len - 1]
      : [0, Math.floor(len / 2), len - 1];
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

  // ---- The honest decision --------------------------------------------------
  const shape = await call("0x" + sel["cfShapeHash()"]);
  assert.equal(shape.ret, fx.cfHash, "the compiled CycleFold records are those of the prover");
  // The fee is exactly decisionFee.
  for (const v of [0n, FEE - 1n, FEE + 1n]) {
    const r = await call(fx.calldata, v);
    assert.equal(r.ok, false, `finalizeRecursive accepted ${v} wei`);
  }
  const res = await call(fx.calldata);
  assert.ok(res.ok, "finalizeRecursive reverted");
  assert.equal(res.ret, fx.systemId, "system id");
  const decided = await call("0x" + sel["decided(bytes32)"] + fx.decidedKey.slice(2));
  assert.equal(BigInt(decided.ret), 1n, "the claim is recorded as decided");
  const calldataBytes = (fx.calldata.length - 2) / 2;
  console.log(`finalizeRecursive    : ${res.gas} gas (${res.exec} execution, ${calldataBytes} bytes of calldata), ${fx.steps} IVC steps`);
  console.log(`proof                : ${fx.proofBytes} bytes (CycleFold argument + one batched decider proof); primary circuit ${fx.primaryConstraints} constraints, closing circuit ${fx.closingConstraints}`);

  // ---- A decided claim is not decided (nor paid for) again --------------------
  const { keccak256 } = require("ethereum-cryptography/keccak.js");
  const selectorOf = (sig) => bytesToHex(keccak256(Buffer.from(sig))).slice(0, 10);
  const again = await call(fx.calldata);
  assert.equal(again.ok, false, "a second submission of a decided claim was accepted");
  assert.equal(again.ret.slice(0, 10), selectorOf("AlreadyDecided()"));
  assert.ok(again.exec < 100_000, `the second submission executed ${again.exec} gas`);
  console.log(`replay               : reverted AlreadyDecided after ${again.exec} gas of execution; the fee is returned`);

  // ---- Circom -> EVM (mode D): a real Circom circuit, end to end ----------------
  // Witnesses from Circom's witness generator, the CycleFold IVC and the
  // recursive proof from `zeno-evm`, decided by the same deployed verifier.
  if (process.env.ZENO_PTAU) {
    const CIRCOM_STEPS = 3;
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
    const t1 = Date.now();
    const out = JSON.parse(
      execFileSync(
        ZENO_EVM,
        ["recursive", "--r1cs", path.join(CIRCOM, "step.r1cs"), "--ptau", process.env.ZENO_PTAU, "--z0", "3", "--wtns", ...wtns],
        { encoding: "utf8", maxBuffer: 1 << 28 }
      )
    );
    fs.rmSync(dir, { recursive: true });
    assert.deepEqual(out.zi, [z.toString()]);
    const resC = await call(out.finalizeRecursive);
    assert.ok(resC.ok, "finalizeRecursive of the Circom circuit reverted");
    assert.equal(resC.ret, out.systemId);
    const decidedC = await call("0x" + sel["decided(bytes32)"] + out.decidedKey.slice(2));
    assert.equal(BigInt(decidedC.ret), 1n, "the Circom claim is recorded as decided");
    console.log(
      `Circom -> EVM (D)    : ${CIRCOM_STEPS} steps of step.circom proven in ${((Date.now() - t1) / 1000).toFixed(1)} s, finalizeRecursive ${resC.gas} gas (primary circuit ${out.primaryConstraints} constraints)`
    );
  } else {
    console.log("Circom -> EVM (D)    : skipped (set ZENO_PTAU to a 2^20-power .ptau)");
  }

  // ---- Circom -> Cloud API -> EVM (mode D) ------------------------------------
  // The real service proves the recursive IVC in the background (202 until
  // done); the client relays its finalizeRecursive call to the contract.
  if (process.env.ZENO_PTAU) {
    const { spawn, execFileSync: run } = require("node:child_process");
    const keys = Object.fromEntries(
      run(LICENSE_BIN, ["keygen"], { encoding: "utf8" }).trim().split("\n").map((l) => l.split("="))
    );
    const token = run(LICENSE_BIN, ["issue", "--customer", "evm-test", "--plan", "recursive", "--days", "1"], {
      encoding: "utf8",
      env: { ...process.env, ZENO_LICENSE_PRIVATE_KEY: keys.ZENO_LICENSE_PRIVATE_KEY },
    }).trim();
    const port = 19000 + (process.pid % 1000);
    const server = spawn(SERVER_BIN, [], {
      env: {
        ...process.env,
        ZENO_LICENSE_PUBLIC_KEY: keys.ZENO_LICENSE_PUBLIC_KEY,
        ZENO_PTAU_PATH: process.env.ZENO_PTAU,
        ZENO_BIND: `127.0.0.1:${port}`,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let serverLog = "";
    server.stderr.on("data", (d) => (serverLog += d));
    try {
      const url = `http://127.0.0.1:${port}`;
      for (let i = 0; ; i++) {
        try {
          if ((await fetch(`${url}/healthz`)).ok) break;
        } catch {}
        if (i > 1200) throw new Error(`the Cloud Prover did not start:\n${serverLog}`);
        await new Promise((r) => setTimeout(r, 100));
      }
      const api = async (route, body) => {
        const res = await fetch(url + route, { method: "POST", headers: { authorization: `Bearer ${token}` }, body });
        const text = await res.text();
        assert.ok(res.status < 300, `${route}: HTTP ${res.status} ${text}`);
        return { status: res.status, body: JSON.parse(text) };
      };
      const t2 = Date.now();
      const created = (await api("/v1/sessions?z0=3&mode=recursive", fs.readFileSync(path.join(CIRCOM, "step.r1cs")))).body;
      const witnessCalculator = require(path.join(CIRCOM, "witness_calculator.js"));
      const calc = await witnessCalculator(fs.readFileSync(path.join(CIRCOM, "step.wasm")));
      const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
      let z = 3n;
      for (let i = 0; i < 2; i++) {
        const secret = BigInt(31 + i);
        await api(`/v1/fold-step?session=${created.session_id}`, await calc.calculateWTNSBin({ step_in: [z.toString()], secret: secret.toString() }, 0));
        z = (z * z * z + z + secret) % P;
      }
      let fin;
      for (;;) {
        fin = await api(`/v1/finalize-evm?session=${created.session_id}`);
        if (fin.status === 200) break;
        assert.equal(fin.status, 202);
        await new Promise((r) => setTimeout(r, 1000));
      }
      assert.deepEqual(fin.body.zi, [z.toString()]);
      const resA = await call(fin.body.finalizeRecursive);
      assert.ok(resA.ok, "the API's finalizeRecursive reverted");
      const decidedA = await call("0x" + sel["decided(bytes32)"] + fin.body.decided_key.slice(2));
      assert.equal(BigInt(decidedA.ret), 1n, "the API's claim is decided");
      console.log(`Circom -> API -> EVM : mode D, 2 steps through the Cloud Prover in ${((Date.now() - t2) / 1000).toFixed(1)} s, finalizeRecursive ${resA.gas} gas, decided`);
    } finally {
      server.kill();
    }
  }

  // ---- Canonical encodings: z_i + r is the same field element as z_i, but
  // it is not a second encoding of the claim --------------------------------
  {
    const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const at = 2 + 2 * (fx.starts[2] + 32 * 3); // state = [i, k, z_0, z_i, …]
    const zi = BigInt("0x" + fx.calldata.slice(at, at + 64));
    const bad = fx.calldata.slice(0, at) + (zi + R).toString(16).padStart(64, "0") + fx.calldata.slice(at + 64);
    const r = await call(bad);
    assert.equal(r.ok, false, "a non-canonical z_i was accepted");
    const { keccak256 } = require("ethereum-cryptography/keccak.js");
    assert.equal(r.ret.slice(0, 10), bytesToHex(keccak256(Buffer.from("MalformedInput()"))).slice(0, 10));
    console.log("non-canonical claim  : rejected as malformed");
  }
  // ---- Protocol fee: paid by every decision, capped, withdrawn by the owner ----
  {
    const balance = async (a) => (await evm.stateManager.getAccount(a))?.balance ?? 0n;
    const decisions = process.env.ZENO_PTAU ? 3n : 1n;
    assert.equal(await balance(verifier.address), FEE * decisions);
    const stranger = Address.fromString("0x00000000000000000000000000000000000000c3");
    await evm.stateManager.putAccount(stranger, new Account(0n, 10n ** 18n));
    const setFee = (fee) => "0x" + sel["setFees(uint256,uint256)"] + word(0n) + word(fee);
    assert.equal(BigInt((await call("0x" + sel["stepFee()"], 0n)).ret), 0n, "no step fee in mode D");
    assert.equal((await call(setFee(FEE), 0n, stranger)).ok, false, "a stranger set the fee");
    const over = await call(setFee(MAX_FEE + 1n), 0n, deployer);
    assert.equal(over.ret.slice(0, 10), selectorOf("FeeAboveCap()"));
    assert.ok((await call(setFee(MAX_FEE), 0n, deployer)).ok);
    const withdraw = "0x" + sel["withdrawFees(address)"] + word(BigInt(deployer.toString()));
    assert.equal((await call(withdraw, 0n, stranger)).ok, false, "a stranger withdrew the fees");
    const before = await balance(deployer);
    assert.ok((await call(withdraw, 0n, deployer)).ok);
    assert.equal(await balance(verifier.address), 0n);
    assert.equal((await balance(deployer)) - before, FEE * decisions);
    console.log(`decision fee         : ${FEE * decisions} wei for ${decisions} decisions, cap ${MAX_FEE} wei enforced`);
  }
  console.log("OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
