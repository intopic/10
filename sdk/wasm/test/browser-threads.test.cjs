// Runs the multi-threaded WASM SDK in headless Chromium: the prover folds
// real Circom witnesses on a Web Worker pool, then the proof is verified.
// The page is served cross-origin isolated, as SharedArrayBuffer requires.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { chromium } = require("playwright");

const ROOT = path.join(__dirname, "../../..");
const DIST = path.join(ROOT, "sdk/wasm/dist/web-threads");
const FIXTURES = path.join(ROOT, "crates/sdk-bindings/fixtures");
const TYPES = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html" };
const MAX_STEP_MS = Number(process.env.MAX_STEP_MS ?? 0);

const PAGE = `<!doctype html><meta charset="utf-8"><script type="module">
import init, { initThreadPool, ZenoLlullProver, ZenoLlullVerifier, wasmMemoryBytes } from "/dist/sdk_bindings.js";
const bytes = async (url) => new Uint8Array(await (await fetch(url)).arrayBuffer());
window.run = async (license) => {
  await init();
  const threads = navigator.hardwareConcurrency;
  await initThreadPool(threads);
  const r1cs = await bytes("/fixtures/step.r1cs");
  const wtns = [];
  for (let i = 0; i < 3; i++) wtns.push(await bytes("/fixtures/step" + i + ".wtns"));
  let t = performance.now();
  const prover = new ZenoLlullProver(license, r1cs, ["3"]);
  const setupMs = performance.now() - t;
  t = performance.now();
  for (const w of wtns) prover.proveStep(w);
  const stepMs = (performance.now() - t) / wtns.length;
  prover.verify();
  t = performance.now();
  const proof = prover.finalize();
  const finalizeMs = performance.now() - t;
  const statement = new ZenoLlullVerifier(r1cs).verify(proof);
  return {
    threads, crossOriginIsolated, setupMs, stepMs, finalizeMs,
    proofBytes: proof.length, steps: statement.steps, zi: statement.zi,
    wasmMiB: wasmMemoryBytes() / 1048576,
  };
};
</script>`;

const server = http.createServer((req, res) => {
  const url = req.url.split("?")[0];
  // Cross-origin isolation is what makes SharedArrayBuffer available.
  const headers = {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
  };
  if (url === "/") {
    res.writeHead(200, { ...headers, "Content-Type": "text/html" });
    return res.end(PAGE);
  }
  const base = url.startsWith("/dist/") ? DIST : url.startsWith("/fixtures/") ? FIXTURES : null;
  const file = base && path.join(base, path.normalize(url.replace(/^\/(dist|fixtures)\//, "")));
  if (!file || !file.startsWith(base) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404, headers);
    return res.end();
  }
  res.writeHead(200, { ...headers, "Content-Type": TYPES[path.extname(file)] ?? "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
});

(async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.error("page error:", e.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForFunction(() => typeof window.run === "function");
    // The prover runs only under a license (a package built without a
    // vendor key checks against the development key: `zeno-license issue --dev`).
    assert.ok(process.env.ZENO_TEST_LICENSE, "set ZENO_TEST_LICENSE (see `zeno-license issue --dev`)");
    const r = await page.evaluate((license) => window.run(license), process.env.ZENO_TEST_LICENSE);
    console.log(`threads          : ${r.threads} (cross-origin isolated: ${r.crossOriginIsolated})`);
    console.log(`setup            : ${r.setupMs.toFixed(0)} ms`);
    console.log(`prover           : ${r.stepMs.toFixed(0)} ms / step`);
    console.log(`finalize (ZK)    : ${r.finalizeMs.toFixed(0)} ms, proof ${r.proofBytes} bytes`);
    console.log(`wasm memory      : ${r.wasmMiB.toFixed(1)} MiB`);
    assert.equal(r.crossOriginIsolated, true);
    assert.equal(r.steps, 3);
    assert.deepEqual(r.zi, ["130308420719099"]);
    assert.ok(r.proofBytes <= 16 * 1024);
    assert.ok(r.wasmMiB <= 512, `wasm memory ${r.wasmMiB} MiB`);
    if (MAX_STEP_MS) assert.ok(r.stepMs <= MAX_STEP_MS, `${r.stepMs} ms/step > ${MAX_STEP_MS}`);
    console.log("OK");
  } finally {
    await browser.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
