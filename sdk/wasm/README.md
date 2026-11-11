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
