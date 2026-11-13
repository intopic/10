# Zeno–Llull Nova IVC — dorëzim për zhvilluesin

Gjendja më 12 nëntor 2026 (përditësuar pas finalizimit EVM të IVC-së rekursive). Ky dokument përmbledh çfarë është ndërtuar, ku
ndodhet projekti, çfarë nuk funksionon ende dhe cilat vendime janë të hapura.
Plani i detajuar me kutitë e shënuara është në [`ROADMAP.md`](../ROADMAP.md);
specifikimi origjinal është *Specifikimi Inxhinierik, Ideja 10*.

## 1. Çfarë është projekti

Një motor provash me njohuri zero i tipit IVC (*Incrementally Verifiable
Computation*) mbi skemën e palosjes Nova: një numër arbitrar hapash
llogaritjeje `z_{i+1} = F(z_i)` paloset në një akumulator me madhësi konstante,
pa FFT dhe pa Trusted Setup në hapat e ndërmjetëm. Rreth tij janë ndërtuar tre
produkte: SDK për shfletues/celular, shërbim cloud me pagesë për provë, dhe
kontrata verifikuese në EVM.

## 2. Depoja dhe mënyra e punës

- Depoja: `intopic/10`. Dega e punës: `claude/pensive-brown-7olueh` (më parë
  `claude/great-goldberg-oyeeic`).
- Rregulli i ndjekur: çdo commit shtyhet në degën e punës, dhe kalon në `main`
  vetëm pasi GitHub Actions del plotësisht e gjelbër.
- `main` është në `5b2cd41`. Puna e CycleFold dhe e finalizimit rekursiv është
  në degë; pronari ka vendosur ta kalojë të gjithën në `main` së bashku pasi CI
  të dalë e gjelbër. Shtytja direkte në `main` nga sesioni bllokohet nga sistemi
  i lejeve, kështu që kalimin e bën pronari.
- Gjuha: Rust (arkworks 0.5), Solidity 0.8.28 (viaIR, Cancun), pak JavaScript
  për testet e kontratave dhe të WASM-it.

## 3. Harta e kodit

| Vendi | Çfarë përmban |
|---|---|
| `crates/core-r1cs` | Matrica të rralla CSR, R1CS e relaksuar `(AZ)∘(BZ) = u·CZ + E`, urë nga `ark-relations` |
| `crates/llull-folder` | Angazhime Pedersen (gjeneratorë me hash-to-curve), termi i kryqëzuar `T`, transkript Poseidon, `nifs_prove` / `nifs_verify`, palosje relaksuar-me-relaksuar, CLI `llull-folder` |
| `crates/zeno-ivc` | Qarku rekursiv `F'`, aritmetikë jo-native (CRT), stepper IVC `ZenoAccumulator` mbi ciklet Pallas/Vesta dhe BN254/Grumpkin, `R1csStep` për qarqe të jashtme, CLI `zeno-ivc` |
| `crates/zeno-ivc/src/cyclefold` | IVC me **CycleFold**: qarku CycleFold, angazhime Hyrax për çdo rresht, qarku primar dhe stepper-i `CycleFoldAccumulator`, qarku mbyllës |
| `crates/zeno-ivc/src/gadgets` | Gadget-e me peshë të ulët: pika afine, shumëzim skalar ELM, MSM me bazë fikse, Poseidon me gjendje të rrafshuar |
| `crates/decider-zk` | Maskimi zero-knowledge, sum-check, IPA, prova e shkurtër transparente `CompressedIvcProof`, CLI `zeno-decider` |
| `crates/evm-verifier` | Anën e provuesit për EVM: transkript Keccak, kodim ABI, KZG dhe ngarkues `.ptau`, qarku vendimtar Groth16, **vendimtari universal** (`src/universal/`), **vendimtari rekursiv** (`src/recursive.rs`) |
| `contracts/` | `ZenoLlullVerifier.sol` (sesione, palosje në zinxhir, tarifë), `ZenoUniversalDecider.sol` (verifikues i vendimtarit universal, edhe `verifyDeferred`), `ZenoBatchedDecider.sol` (një provë universale për disa qarqe) dhe `ZenoRecursiveVerifier.sol` (`finalizeRecursive`, me matricat CycleFold në `ZenoCycleFoldShape.sol`, të gjeneruar), me teste në EVM lokale |
| `crates/sdk-bindings`, `sdk/wasm` | Hyrje nga Circom (`.r1cs` / `.wtns`), API WebAssembly, paketa `@zenollull/wasm-sdk` (me variant me shumë fije) |
| `crates/mobile-ffi`, `sdk/native`, `sdk/android` | SDK native me UniFFI: lidhje Swift, Kotlin, Python; paketim AAR dhe XCFramework |
| `crates/zeno-license` | Çelësa licence të nënshkruar Ed25519 dhe mjeti i shitësit |
| `crates/cloud-prover`, `Dockerfile` | Shërbimi HTTP me pagesë për provë, autentikim me licencë, matje përdorimi |
| `scripts/` | Skriptet e ndërtimit për WASM, SDK native, AAR, XCFramework dhe testi i kontejnerit |
| `.github/workflows/ci.yml` | 11 punë: lint, teste, WASM, KPI, kontrata, IVC rekursive mbi PPoT 2^20, SDK native, Android, iOS, Cloud Prover |

Rreth 8 900 rreshta Rust dhe Solidity, 43 teste Rust plus testet në Node,
Python dhe EVM.

## 4. Katër mënyrat e përdorimit

Është e rëndësishme të dallohen, sepse kanë garanci të ndryshme.

**A. IVC rekursive off-chain (transparente).** `zeno-ivc` + `decider-zk`.
Çdo hap verifikon palosjen e hapit të mëparshëm brenda qarkut. Prova
përfundimtare (`CompressedIvcProof`, rreth 10 KB) verifikohet jashtë zinxhirit.
Nuk ka asnjë setup. **Nuk verifikohet në EVM.**

**B. Palosje në zinxhir + vendimtar universal.** Kontrata është vetë
verifikuesi i palosjes: `verifyFoldedProof` (ose `verifyFoldedProofBatch`)
palos çdo hap në një akumulator të ruajtur në kontratë, dhe `finalizeUniversal`
verifikon në zinxhir që akumulatori përfundimtar është i kënaqshëm. Angazhimet
janë KZG mbi një `.ptau` publike. Nuk ka çelësa për qark. Kostoja në zinxhir
është lineare në numrin e hapave.

**C. Palosje në zinxhir + Groth16 (`finalizeWithProof`).** Vetëm për zhvillim:
çelësat janë specifikë për qarkun dhe gjenerohen me një palë të vetme.

**D. IVC rekursive me CycleFold + `finalizeRecursive`.** `zeno-ivc::cyclefold` +
`evm-verifier::recursive` + `ZenoRecursiveVerifier.sol`. Provuesi palos N hapa
jashtë zinxhirit; kontrata vendos gjendjen përfundimtare me një thirrje, me
kosto **të pavarur nga N** (3.57 M gas). Reference string: `.ptau` publike me
2^20 fuqi. Nuk ka çelësa për qark. Sistemi identifikohet me `keccak256(vk
primar ‖ vk mbyllës ‖ hash i matricave CycleFold)`, që kushdo e rillogarit.

## 5. Matjet

Të gjitha janë matur në 4 vCPU, përveç ku shënohet ndryshe.

| Çfarë | Vlera |
|---|---|
| Qarku rekursiv primar | 11 217 kufizime (54% hash-e Poseidon) |
| Hap IVC, hap me 2^16 kufizime | rreth 307–415 ms; 946 → 553 → 307 ms për 1 / 2 / 4 fije |
| Memoria e provuesit | konstante në numrin e hapave; rreth 225 MiB (2^16), e kufizuar ≤ 512 MiB në CI |
| `nifs_verify` | rreth 0.5 ms |
| Prova transparente (mënyra A) | rreth 10 KB |
| WASM, një fije / katër fije | rreth 0.9 s / rreth 350–390 ms për hap, rreth 170 MiB |
| SDK native (qark Circom minimal) | rreth 93 ms për hap |
| `verifyFoldedProof` | rreth 74k gas (198k hapi i parë) |
| `verifyFoldedProofBatch` | rreth 22.9k gas për hap (100 hapa = 2.29 M) |
| `finalizeUniversal` | 0.82 M gas / 6.7 KB (16 kufizime) → 1.89 M gas / 21.6 KB (65 536 kufizime) |
| `finalizeWithProof` (Groth16, zhvillim) | rreth 456k gas, 544 bajt |
| Qarku CycleFold / qarku primar CycleFold për hap (C = 128) | 936 kufizime / 66 791 kufizime, 468k elemente jo-zero |
| Qarku mbyllës | 136 974 kufizime, 782k elemente jo-zero, 350 hyrje publike; 28 s provim, 1.94 GB memorie |
| Provuesi i `finalizeRecursive` (pas hapave) | rreth 40 s; verifikim native 14 ms |
| `finalizeRecursive` | **3.57 M gas** (2.93 M ekzekutim + 39 KB calldata), i njëjtë për çdo numër hapash; një provë universale e grupuar për qarkun primar dhe atë mbyllës; matricat CycleFold nga struktura uniforme (230 rekorde) |

Gazi i `finalizeUniversal` rritet logaritmikisht: rreth 89k gas dhe 1.25 KB
për çdo dyfishim të qarkut. Matja për 65 536 kufizime është bërë mbi skedarin
publik `ppot_0080_18.ptau` të ceremonisë Perpetual Powers of Tau.

## 6. KPI-të e specifikimit

| KPI | Gjendja |
|---|---|
| Faza 1: `(AZ)∘(BZ) = u·CZ + E` me 0 gabime pas 100 hapash | arritur, në katër kurba |
| Memorie ≤ 512 MB | arritur (Rust dhe WASM) |
| Koha < 50 ms për hap në 2^16 | **e pa arritur** në 4 vCPU; pronari e ka pranuar vlerën aktuale |
| "4 000 kufizime për hap" | **e pa arritur** (11 217); pronari e ka pranuar |
| Provë < 4 KB | vetëm në mënyrën Groth16 të zhvillimit; mënyrat e tjera 6.7–21.6 KB |
| EVM < 300k gas | arritur për hapin e palosjes; vendimi final kushton 0.82–1.89 M (mënyra B) dhe 3.57 M (mënyra D, për çdo N) |

## 7. Çfarë duhet ditur para se të prekësh kodin

- **Nuk ka pasur auditim sigurie.** Kodi kriptografik është shkruar dhe testuar
  nga i njëjti autor. Testet mbulojnë plotësinë dhe falsifikimin e çdo
  komponenti të provave, por nuk zëvendësojnë një auditim.
- **Një e çarë u gjet dhe u mbyll** (`82ffe9d`): vendimtari Groth16 krahasonte
  dëshminë me angazhimet në një pikë që provuesi e dinte paraprakisht. Tani
  dëshmia lidhet me një hash Poseidon para se të nxirret pika. Mësimi vlen për
  çdo ndryshim: çdo gjë që futet si dëshmi në një SNARK duhet fiksuar para
  sfidës.
- **Çelësat dhe SRS-të e testimit.** `Srs::insecure_for_testing` dhe
  `DeciderKeys::insecure_for_testing` gjenerojnë sekrete lokalisht dhe janë
  vetëm për teste. Skedari `pot7_test.ptau` në depo është një ceremoni lodër.
- **Identiteti i qarkut në mënyrën B.** Sesioni hapet me
  `vk = keccak256(çelësi i qarkut)`; vetëm ai çelës mund ta vendosë. Pala që
  mbështetet te një sesion duhet ta rillogarisë vetë këtë identitet nga qarku
  dhe `.ptau` dhe ta krahasojë.
- **Transkriptet duhet të përputhen bajt për bajt** mes Rust-it
  (`evm-verifier`) dhe Solidity-t. Testi `contracts/test/verifier.test.cjs`
  ekzekuton kontratat në një EVM lokale kundrejt provave të Rust-it dhe është
  rrjeta kryesore e sigurisë për këtë.
- Poseidon i përdorur është varianti i `ark-crypto-primitives` (jo Poseidon2,
  siç përmend specifikimi), me parametra të gjeneruar për çdo fushë.
- **Sfidat e palosjes në mënyrën D** kanë formën `r = 2^128 + 2t + 1` me `t`
  127-bitësh. Kjo e bën të pamundur me ndërtim çdo rast përjashtimor të
  formulave jo të plota të gadget-eve. Mos e ndrysho formën pa ndryshuar edhe
  argumentin në `gadgets::ec`.
- **Matricat CycleFold** janë konstante në `ZenoCycleFoldShape.sol`, e gjeneruar
  nga `evm-verifier::cf_uniform` (testi `cf_uniform` dështon nëse qarku
  ndryshon pa e rigjeneruar). Hash-i i tyre hyn në transkript dhe në
  identitetin e sistemit. Rekordet nxirren nga matricat dhe kontrollohen që i
  riprodhojnë saktësisht. Renditja e qarkut (`circuit::layout`) e bën
  përshkrimin të vogël, por saktësia nuk varet prej saj: një ndryshim në qark
  jep thjesht më shumë rekorde eksplicite.
- **SHA-256 i `ppot_0080_20.ptau`** në CI u llogarit nga shkarkimi më 12
  nëntor 2026. Mbron nga ndryshimet e mëvonshme, jo nga skedari origjinal.
  Struktura e fuqive kontrollohet gjithsesi nga `Srs::from_ptau`.
- `finalizeUniversal` është matur deri në 65 536 kufizime. Qarqe më të mëdha
  kërkojnë `.ptau` me më shumë fuqi (nevojiten rreth 4× numri i kufizimeve).

## 8. Çfarë nuk është bërë

1. **Ulje e mëtejshme e gazit të `finalizeRecursive`** (sot 3.57 M, nga të
   cilat vendimtari i grupuar 2.22 M): qarku mbyllës nën 2^19 elemente
   jo-zero (kryesisht RAM dhe kohë e provuesit). Dy provat universale janë
   bashkuar në një dhe matricat CycleFold vlerësohen nga struktura uniforme.
2. **Ulje e mëtejshme e gazit të `finalizeUniversal`**: reduktimi i pesë
   pretendimeve të vlerësimit në më pak pika.
3. **Publikimi**: paketa NPM, imazhi Docker, AAR dhe XCFramework ndërtohen në
   CI si artefakte, por nuk janë publikuar askund.
4. **Hyrje nga Noir dhe ONNX (zkML)**; vetëm Circom mbështetet.
5. **Avancimet opsionale të specifikimit**: CCS/HyperNova, SuperNova, SIMD.
6. **Optimizimi i MSM-së** (koha e hapit). Tabelat me bazë fikse dhe GLV nuk
   ndihmojnë për MSM të mëdha; përfitimi real do të vinte nga mbledhja
   *batch-affine* (rreth 1.5×) ose nga më shumë bërthama.

## 9. Vendime të hapura për pronarin

1. **Finalizimi EVM i IVC-së rekursive** është ndërtuar (mënyra D). Mbetet
   vendimi nëse ia vlen investimi në uljen e mëtejshme të gazit (pika 8.1).
2. **Mënyra Groth16 (`finalizeWithProof`)**: të hiqet nga kontrata, apo të
   mbetet si mënyrë zhvillimi? Sot është e shënuar "vetëm për zhvillim" dhe
   regjistrimi i çelësave të saj bëhet nga pronari i kontratës.
3. **Auditimi**: kur dhe nga kush, para çdo vendosjeje me vlerë reale.
4. **Publikimi dhe çelësat**: tokeni i organizatës `@zenollull` në NPM dhe
   çelësi privat i licencave të shitësit nuk ekzistojnë ende; mjeti
   `zeno-license keygen` e gjeneron të dytin.
5. **Zinxhiri i synuar**: mënyra D kushton 3.57 M gas, i njëjtë për çdo N.
   Mënyra B kushton 0.8–1.9 M për vendimin final plus rreth 23k gas për çdo
   hap, prandaj mënyra D del më e lirë kur N kalon rreth 75–120 hapa. Të dyja
   janë praktike kryesisht në L2.

## 10. Si ndërtohet dhe testohet

```bash
cargo test --workspace
```

```bash
cargo run --release -p zeno-ivc -- prove --steps 100 --log-constraints 12 --cycle pasta
```

```bash
cargo run --release -p decider-zk -- --steps 20 --log-constraints 12 --cycle pasta
```

Kontratat (kërkon Node 22):

```bash
cargo build --release -p evm-verifier
```

```bash
cd contracts && npm ci && node test/verifier.test.cjs
```

Për matjen në 2^16 kufizime, vendos `ZENO_PTAU` te skedari
`ppot_0080_18.ptau` (URL-ja dhe SHA-256 janë në `.github/workflows/ci.yml`).

IVC-ja rekursive dhe `finalizeRecursive` (mënyra D) kërkojnë 2^20 fuqi. Pa
`ZENO_PTAU` përdoret një reference string testimi i krijuar lokalisht; me të,
skedari `ppot_0080_20.ptau`:

```bash
cargo test --release -p evm-verifier --test closing_decider --test recursive -- --ignored --nocapture
```

```bash
cargo build --release -p evm-verifier && node contracts/test/recursive.test.cjs
```

SDK-të:

```bash
./scripts/build-wasm-sdk.sh && node sdk/wasm/test/ivc.test.cjs
```

```bash
./scripts/build-native-sdk.sh && python3 sdk/native/test/test_sdk.py
```

Varianti WASM me shumë fije kërkon Rust nightly (`build-wasm-sdk-threads.sh`);
AAR kërkon Android NDK dhe Gradle; XCFramework kërkon macOS me Xcode.

## 11. Ku të fillosh leximin

1. `crates/llull-folder/src/nifs_engine.rs` — palosja, bërthama e gjithçkaje.
2. `crates/zeno-ivc/src/nova_ivc_circuit.rs` dhe `ivc_stepper.rs` — rekursioni.
3. `crates/evm-verifier/src/universal/decider.rs` — vendimtari universal;
   komenti në krye të skedarit përshkruan protokollin.
4. `contracts/ZenoUniversalDecider.sol` — i njëjti protokoll në Solidity.
5. `contracts/test/verifier.test.cjs` — rrjedha e plotë në EVM, me matjet.
