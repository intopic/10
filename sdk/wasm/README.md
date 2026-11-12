# @zenollull/wasm-sdk

Provues dhe verifikues IVC i Zeno–Llull për shfletues dhe Node.js, mbi ciklin
BN254/Grumpkin. Funksioni i hapit jepet si qark Circom me ndërfaqen
`signal input step_in[k]` (publik) dhe `signal output step_out[k]`.

```js
const { ZenoLlullProver, ZenoLlullVerifier } = require("@zenollull/wasm-sdk");

const prover = new ZenoLlullProver(r1csBytes, ["3"]);   // gjendja fillestare z0
prover.proveStep(wtnsBytes);                            // një herë për çdo hap
const proof = prover.finalize();                        // provë zero-knowledge

const st = new ZenoLlullVerifier(r1csBytes).verify(proof);  // hedh gabim nëse është e pavlefshme
console.log(st.steps, st.z0, st.zi);
```

Ndërtimi dhe testimi:

```bash
./scripts/build-wasm-sdk.sh
```

```bash
node sdk/wasm/test/ivc.test.cjs
```

## Shumë fije në shfletues

Varianti `@zenollull/wasm-sdk/threads` e ekzekuton provuesin mbi një grup Web Worker-ash
(rreth 2.3× më shpejt me 4 fije). Faqja duhet të jetë *cross-origin isolated*
(`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`).

```js
import init, { initThreadPool, ZenoLlullProver } from "@zenollull/wasm-sdk/threads";
await init();
await initThreadPool(navigator.hardwareConcurrency);
```

```bash
./scripts/build-wasm-sdk-threads.sh
```

```bash
node sdk/wasm/test/browser-threads.test.cjs
```
