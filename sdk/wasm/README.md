# @zenollull/wasm-sdk

Provues dhe verifikues IVC i Zeno–Llull për shfletues dhe Node.js, mbi ciklin
BN254/Grumpkin. Funksioni i hapit jepet si qark Circom me ndërfaqen
`signal input step_in[k]` (publik) dhe `signal output step_out[k]`.

```js
const { ZenoLlullProver, ZenoLlullVerifier } = require("@zenollull/wasm-sdk");

const prover = new ZenoLlullProver(licenseKey, r1csBytes, ["3"]);   // licenca dhe gjendja fillestare z0
prover.proveStep(wtnsBytes);                            // një herë për çdo hap
const proof = prover.finalize();                        // provë zero-knowledge

const st = new ZenoLlullVerifier(r1csBytes).verify(proof);  // hedh gabim nëse është e pavlefshme
console.log(st.steps, st.z0, st.zi);                    // steps: number (i saktë deri në 2^53)

// Pauzë dhe vazhdim (edhe në një pajisje tjetër): gjendja kontrollohet plotësisht.
const saved = prover.saveState();                       // SEKRET: përmban dëshmitë e palosura
const again = ZenoLlullProver.resume(licenseKey, r1csBytes, saved);
```

Prova fillon me formatin e saj: `ZLP` dhe versioni `1`. Një provë e një versioni
tjetër refuzohet me mesazhin `proof format version N is not supported`, jo si e
korruptuar. Gjatësitë e brendshme të provës dhe të gjendjes kontrollohen para
deserializimit, kështu që bajtet armiqësore japin gabim, jo ndërprerje të procesit.

Provuesi punon vetëm me një `EnterpriseLicenseKey` të vlefshme. Licenca kontrollohet
kundrejt çelësit publik të shitësit të ngulitur në paketë dhe orës së sistemit; kuota
`maxSteps` e licencës zbatohet në çdo hap. `verifyLicense(key)` kthen çfarë jep licenca.

Paketa e lëshimit ndërtohet me `ZENO_VENDOR_PUBLIC_KEY=<hex>`. Pa të, paketa përdor
çelësin e zhvillimit (`developmentBuild: true`), për të cilin kushdo lëshon licenca me
`zeno-license issue --dev`.

Ndërtimi dhe testimi (`ZENO_TEST_LICENSE` është një licencë zhvillimi):

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
