// Deploys the Zeno–Llull verifiers on an L2 with the launch fees of
// deploy/l2.json:
//
//   ZenoUniversalDecider  -> ZenoLlullVerifier(stepFee, decisionFee, maxFee, decider)      (mode B)
//   ZenoBatchedDecider    -> ZenoRecursiveVerifier(decider, stepFee, decisionFee, maxFee)  (mode D)
//
// The fees are written in dollars and converted to wei with the ETH price of
// the day (--eth-usd). The launch is L2 only: Ethereum mainnet is refused.
//
// Dry run (in-process EVM, no keys, no network), as CI runs it:
//   node scripts/deploy.cjs --dry-run [--eth-usd 3000]
// Live:
//   RPC_URL=https://... DEPLOYER_KEY=0x... node scripts/deploy.cjs --eth-usd 3125 --owner 0xSafe...
// --owner hands both contracts to that address (a multisig) once deployed.
// The addresses are written to deploy/deployments/<chainId>.json.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const solc = require("solc");
const { EVM } = require("@ethereumjs/evm");
const { Common, Chain, Hardfork } = require("@ethereumjs/common");
const { FeeMarketEIP1559Transaction } = require("@ethereumjs/tx");
const { Address, Account, hexToBytes, bytesToHex, privateToAddress } = require("@ethereumjs/util");

const ROOT = path.join(__dirname, "..");
const ETHEREUM_MAINNET = 1n;

function args() {
  const a = process.argv.slice(2);
  const value = (name) => {
    const i = a.indexOf(name);
    return i >= 0 ? a[i + 1] : undefined;
  };
  return {
    dryRun: a.includes("--dry-run"),
    ethUsd: value("--eth-usd") ?? process.env.ETH_USD,
    owner: value("--owner") ?? process.env.OWNER,
    config: value("--config") ?? path.join(ROOT, "deploy/l2.json"),
  };
}

/// Dollars to wei at `ethUsd` dollars per ETH, in micro-dollar steps.
function toWei(usd, ethUsd) {
  const micro = (x) => BigInt(Math.round(x * 1e6));
  return (micro(usd) * 10n ** 18n) / micro(ethUsd);
}

function fees(config, ethUsd) {
  const one = (c) => {
    const f = {
      contract: c.contract,
      stepFee: toWei(c.stepFeeUsd, ethUsd),
      decisionFee: toWei(c.decisionFeeUsd, ethUsd),
      maxFee: toWei(c.maxFeeUsd, ethUsd),
      usd: c,
    };
    if (f.stepFee > f.maxFee || f.decisionFee > f.maxFee) throw new Error(`${c.contract}: a fee is above maxFee`);
    return f;
  };
  return { universal: one(config.universal), recursive: one(config.recursive) };
}

function compile() {
  const files = [
    "ZenoUniversalDecider.sol",
    "ZenoLlullVerifier.sol",
    "ZenoBatchedDecider.sol",
    "ZenoRecursiveVerifier.sol",
    "ZenoCycleFoldShape.sol",
    "lib/ZenoBn254.sol",
    "lib/ZenoFees.sol",
  ];
  const sources = Object.fromEntries(files.map((f) => [f, { content: fs.readFileSync(path.join(ROOT, f), "utf8") }]));
  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      evmVersion: "cancun",
      outputSelection: { "*": { "*": ["evm.bytecode.object", "evm.deployedBytecode.object", "evm.methodIdentifiers"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  const get = (file, name) => {
    const c = out.contracts[file][name];
    const runtime = c.evm.deployedBytecode.object.length / 2;
    assert.ok(runtime <= 24576, `${name} exceeds the contract size limit (${runtime} bytes)`);
    return { bytecode: c.evm.bytecode.object, sel: c.evm.methodIdentifiers };
  };
  return {
    universalDecider: get("ZenoUniversalDecider.sol", "ZenoUniversalDecider"),
    universal: get("ZenoLlullVerifier.sol", "ZenoLlullVerifier"),
    batchedDecider: get("ZenoBatchedDecider.sol", "ZenoBatchedDecider"),
    recursive: get("ZenoRecursiveVerifier.sol", "ZenoRecursiveVerifier"),
  };
}

const word = (v) => BigInt(v).toString(16).padStart(64, "0");

/// Constructor calls in deployment order; `$name` is the address of an earlier one.
function plan(c, f) {
  return [
    { name: "ZenoUniversalDecider", code: c.universalDecider.bytecode, args: [] },
    {
      name: "ZenoLlullVerifier",
      code: c.universal.bytecode,
      args: [f.universal.stepFee, f.universal.decisionFee, f.universal.maxFee, "$ZenoUniversalDecider"],
    },
    { name: "ZenoBatchedDecider", code: c.batchedDecider.bytecode, args: [] },
    {
      name: "ZenoRecursiveVerifier",
      code: c.recursive.bytecode,
      args: ["$ZenoBatchedDecider", f.recursive.stepFee, f.recursive.decisionFee, f.recursive.maxFee],
    },
  ];
}

const initCode = (step, deployed) =>
  "0x" + step.code + step.args.map((a) => word(typeof a === "string" ? deployed[a.slice(1)] : a)).join("");

// ---- Chain access: an in-process EVM, or JSON-RPC with a signing key --------

async function localChain() {
  const evm = await EVM.create({ common: new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Cancun }) });
  const from = Address.fromString("0x00000000000000000000000000000000000000a1");
  await evm.stateManager.putAccount(from, new Account(0n, 10n ** 20n));
  const run = async (to, data) => {
    const res = await evm.runCall({ caller: from, to, data: hexToBytes(data), gasLimit: 30_000_000n });
    if (res.execResult.exceptionError) throw new Error(`reverted: ${res.execResult.exceptionError.error}`);
    return res;
  };
  return {
    chainId: 0n,
    from: from.toString(),
    deploy: async (data) => (await run(undefined, data)).createdAddress.toString(),
    send: async (to, data) => void (await run(Address.fromString(to), data)),
    call: async (to, data) => bytesToHex((await run(Address.fromString(to), data)).execResult.returnValue),
  };
}

async function rpcChain(url, key) {
  let id = 0;
  const rpc = async (method, params = []) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
    });
    const body = await res.json();
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
  };
  const chainId = BigInt(await rpc("eth_chainId"));
  if (chainId === ETHEREUM_MAINNET) throw new Error("this launch is L2 only: refusing Ethereum mainnet");
  const secret = hexToBytes(key.startsWith("0x") ? key : "0x" + key);
  const from = new Address(privateToAddress(secret)).toString();
  const common = Common.custom({ chainId }, { baseChain: Chain.Mainnet, hardfork: Hardfork.Cancun });
  const transact = async (to, data) => {
    const nonce = await rpc("eth_getTransactionCount", [from, "pending"]);
    const gas = BigInt(await rpc("eth_estimateGas", [{ from, to, data }]));
    const tip = BigInt(await rpc("eth_maxPriorityFeePerGas"));
    const base = BigInt((await rpc("eth_getBlockByNumber", ["latest", false])).baseFeePerGas);
    const tx = FeeMarketEIP1559Transaction.fromTxData(
      { nonce, to, data, gasLimit: (gas * 12n) / 10n, maxPriorityFeePerGas: tip, maxFeePerGas: 2n * base + tip },
      { common }
    ).sign(secret);
    const hash = await rpc("eth_sendRawTransaction", [bytesToHex(tx.serialize())]);
    for (;;) {
      const receipt = await rpc("eth_getTransactionReceipt", [hash]);
      if (receipt) {
        if (receipt.status !== "0x1") throw new Error(`transaction ${hash} reverted`);
        return receipt;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  };
  return {
    chainId,
    from,
    deploy: async (data) => (await transact(undefined, data)).contractAddress,
    send: async (to, data) => void (await transact(to, data)),
    call: (to, data) => rpc("eth_call", [{ to, data }, "latest"]),
  };
}

// ---- Deployment and the checks that follow it ---------------------------------

async function main() {
  const a = args();
  if (!a.dryRun && !a.ethUsd) throw new Error("give the ETH price of the day: --eth-usd <dollars>");
  const ethUsd = Number(a.ethUsd ?? 3000);
  assert.ok(ethUsd > 0, "--eth-usd must be a positive number");
  const f = fees(JSON.parse(fs.readFileSync(a.config, "utf8")), ethUsd);
  const c = compile();

  let chain;
  if (a.dryRun) chain = await localChain();
  else {
    if (!process.env.RPC_URL || !process.env.DEPLOYER_KEY) throw new Error("set RPC_URL and DEPLOYER_KEY");
    chain = await rpcChain(process.env.RPC_URL, process.env.DEPLOYER_KEY);
  }
  console.log(`${a.dryRun ? "dry run (in-process EVM)" : `chain ${chain.chainId}`}, deployer ${chain.from}, ETH = $${ethUsd}`);

  const deployed = {};
  for (const step of plan(c, f)) {
    deployed[step.name] = await chain.deploy(initCode(step, deployed));
    console.log(`${step.name.padEnd(22)} ${deployed[step.name]}`);
  }

  // Read the fees back from the contracts.
  const read = async (to, sel, sig, ...xs) => BigInt(await chain.call(to, "0x" + sel[sig] + xs.map(word).join("")));
  const check = async (key, contract) => {
    const sel = c[key].sel;
    const to = deployed[contract];
    for (const name of ["stepFee", "decisionFee", "maxFee"]) {
      assert.equal(await read(to, sel, `${name}()`), f[key][name], `${contract}.${name}`);
    }
    assert.equal(await read(to, sel, "owner()"), BigInt(chain.from), `${contract}.owner`);
  };
  await check("universal", "ZenoLlullVerifier");
  await check("recursive", "ZenoRecursiveVerifier");
  const r = f.recursive;
  const quote = (n) => read(deployed.ZenoRecursiveVerifier, c.recursive.sel, "recursiveFee(uint256)", n);
  assert.equal(await quote(1000), r.decisionFee + 1000n * r.stepFee, "recursiveFee(1000)");
  assert.equal(await quote(10n ** 9n), r.maxFee, "recursiveFee is capped");

  const usd = (wei) => `$${((Number(wei) / 1e18) * ethUsd).toFixed(4)}`;
  console.log("\nfees (wei, and dollars at the given ETH price):");
  for (const [mode, x] of [["B", f.universal], ["D", f.recursive]]) {
    console.log(
      `  mode ${mode} ${x.contract.padEnd(22)} stepFee ${x.stepFee} (${usd(x.stepFee)})  decisionFee ${x.decisionFee} (${usd(x.decisionFee)})  maxFee ${x.maxFee} (${usd(x.maxFee)})`
    );
  }
  const capSteps = r.stepFee > 0n ? (r.maxFee - r.decisionFee) / r.stepFee : 0n;
  console.log(`  mode D: 1,000 steps cost ${usd(await quote(1000))}; the cap is reached at ${capSteps} steps`);

  if (a.owner) {
    const to = Address.fromString(a.owner).toString();
    for (const [key, contract] of [["universal", "ZenoLlullVerifier"], ["recursive", "ZenoRecursiveVerifier"]]) {
      await chain.send(deployed[contract], "0x" + c[key].sel["transferOwnership(address)"] + word(to));
      assert.equal(await read(deployed[contract], c[key].sel, "owner()"), BigInt(to), `${contract} handed over`);
    }
    console.log(`\nowner of both verifiers: ${to}`);
  }

  if (!a.dryRun) {
    const dir = path.join(ROOT, "deploy/deployments");
    fs.mkdirSync(dir, { recursive: true });
    const record = {
      chainId: chain.chainId.toString(),
      ethUsd,
      owner: a.owner ?? chain.from,
      contracts: deployed,
      fees: Object.fromEntries(
        Object.entries(f).map(([k, x]) => [x.contract, { stepFee: `${x.stepFee}`, decisionFee: `${x.decisionFee}`, maxFee: `${x.maxFee}` }])
      ),
    };
    const file = path.join(dir, `${chain.chainId}.json`);
    fs.writeFileSync(file, JSON.stringify(record, null, 2) + "\n");
    console.log(`\nwritten ${path.relative(ROOT, file)}`);
  }
  console.log("OK");
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
