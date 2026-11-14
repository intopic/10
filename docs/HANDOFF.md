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
| `crates/evm-verifier` | Anën e provuesit për EVM: transkript Keccak, kodim ABI, KZG dhe ngarkues `.ptau`, **vendimtari universal** (`src/universal/`), **vendimtari rekursiv** (`src/recursive.rs`) |
| `contracts/lib/` | `ZenoBn254.sol`: aritmetika BN254 përmes precompile-ve (`ZenoBn254`) dhe ndihmësit e sum-check-ut me modul fiks (`ZenoFr`, `ZenoFq`), të përbashkët për të gjitha kontratat |
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
është lineare në numrin e hapave. Nga një qark Circom: `zeno-evm key` (vk dhe
`openSession`) dhe `zeno-evm universal` (calldata e palosjes dhe e
`finalizeUniversal` nga skedarët `.r1cs` / `.wtns`). **Në pajisje** (wallet,
shfletues, telefon): `ZenoLlullOnChainProver` në WASM dhe `OnChainProver` në
Swift/Kotlin/Python prodhojnë të njëjtat thirrje pa API, dhe dëshmitë nuk
largohen nga pajisja; mjafton `.ptau`-ja e shkurtuar e qarkut (`zeno-evm
trim-ptau`). Edhe përmes Cloud API-së: `mode=universal`.

**C. Palosje në zinxhir + Groth16 (`finalizeWithProof`).** Vetëm për zhvillim:
çelësat janë specifikë për qarkun dhe gjenerohen me një palë të vetme. Nuk
është pjesë e prodhimit: në Rust është pas feature-it `dev-groth16` (joaktiv
si parazgjedhje), në zinxhir vetëm te kontrata
`contracts/dev/ZenoLlullVerifierDevGroth16.sol`. `ZenoLlullVerifier.sol` nuk
ka as `finalizeWithProof`, as regjistër çelësash.

Emërtimi A / B / C / D është i njëjtë kudo: në kod, në teste dhe në dokumente.

**D. IVC rekursive me CycleFold + `finalizeRecursive`.** `zeno-ivc::cyclefold` +
`evm-verifier::recursive` + `ZenoRecursiveVerifier.sol`. Provuesi palos N hapa
jashtë zinxhirit; kontrata vendos gjendjen përfundimtare me një thirrje, me
kosto **të pavarur nga N** (3.64 M gas). Reference string: `.ptau` publike me
2^20 fuqi. Nuk ka çelësa për qark. Sistemi identifikohet me `keccak256(vk
primar ‖ vk mbyllës ‖ hash i matricave CycleFold)`, që kushdo e rillogarit.
Nga një qark Circom: `zeno-evm recursive` ose Cloud API me `mode=recursive`
(jo në pajisje: rreth 2 GB RAM). Një pretendim i vendosur më parë refuzohet me
`AlreadyDecided` pas rreth 8k gaz, kështu që tarifa i kthehet dërguesit.

**Tarifat.** `ZenoLlullVerifier` merr `protocolFee` për çdo hap dhe për çdo
finalizim (`finalize`, `finalizeUniversal`); `ZenoRecursiveVerifier` për çdo
`finalizeRecursive`. Të dyja trashëgojnë `contracts/lib/ZenoFees.sol`: pronari
ndryshon tarifën dhe tërheq fondet, por kurrë mbi `maxFee`, të fiksuar në
vendosje, dhe nuk prek asgjë nga verifikimi. Konstruktorët:
`ZenoLlullVerifier(fee, maxFee, decider)`, `ZenoRecursiveVerifier(decider,
fee, maxFee)`. Kushdo mund të vendosë kopjen e vet pa tarifë; tarifa paguan
regjistrimin në kontratën tonë.

**Mjeti `zeno-evm`** (`crates/zeno-evm`) është mjeti i
prodhimit për mënyrat B dhe D: merr të njëjtët skedarë Circom si SDK-ja dhe
Cloud Prover, kontrollon çdo dëshmi (vazhdimësinë e gjendjes dhe kufizimet)
para provimit dhe përdor rastësinë e sistemit operativ. `zeno-evm-fixture`
mbetet mjet testi (farë e fiksuar, jo ZK).

## 5. Matjet

Të gjitha janë matur në 4 vCPU, përveç ku shënohet ndryshe.

| Çfarë | Vlera |
|---|---|
| Qarku rekursiv primar | 11 217 kufizime (54% hash-e Poseidon) |
| Hap IVC, hap me 2^16 kufizime | rreth 307–440 ms; 946 → 553 → 307 ms për 1 / 2 / 4 fije; me `batch-affine-msm` 440 → 394 ms |
| Memoria e provuesit | konstante në numrin e hapave; rreth 225 MiB (2^16), e kufizuar ≤ 512 MiB në CI |
| `nifs_verify` | rreth 0.5 ms |
| Prova transparente (mënyra A) | rreth 10 KB |
| WASM, një fije / katër fije | rreth 0.9 s / rreth 350–390 ms për hap, rreth 170 MiB |
| SDK native (qark Circom minimal) | rreth 93 ms për hap |
| `verifyFoldedProof` | rreth 74k gas (198k hapi i parë) |
| `verifyFoldedProofBatch` | rreth 22.9k gas për hap (100 hapa = 2.29 M) |
| `finalizeUniversal` | 0.82 M gas / 6.7 KB (16 kufizime) → 1.89 M gas / 21.6 KB (65 536 kufizime) |
| `finalizeWithProof` (Groth16, zhvillim) | rreth 456k gas, 544 bajt |
| Qarku CycleFold / qarku primar CycleFold për hap (C = 128) | 943 kufizime (936 variabla) / 66 791 kufizime, 468k elemente jo-zero |
| Qarku mbyllës | 136 974 kufizime, 782k elemente jo-zero, 350 hyrje publike; 28 s provim, 1.94 GB memorie |
| Provuesi i `finalizeRecursive` (pas hapave) | rreth 23 s (31 s para paralelizimit të vendimtarit); verifikim native 14 ms |
| `finalizeRecursive` | **3.64 M gas** (3.01 M ekzekutim + 39 KB calldata), i njëjtë për çdo numër hapash; një provë universale e grupuar për qarkun primar dhe atë mbyllës; matricat CycleFold nga struktura uniforme (230 rekorde) |

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
| EVM < 300k gas | arritur për hapin e palosjes; vendimi final kushton 0.82–1.89 M (mënyra B) dhe 3.64 M (mënyra D, për çdo N) |

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
- **Numri i hyrjeve publike është pjesë e çelësit** (fjala e 24-t, `num_io`).
  Hyrjet publike përtej atyre të qarkut bien në kolona të `Z` që asnjë
  kufizim nuk i prek. Para këtij ndryshimi një sesion i hapur me aritet më të
  madh se i qarkut dilte `decided` me gjendje arbitrare. Tani të dy
  vendimtarët kërkojnë `acc.length == 5 + num_io` dhe e thithin gjithë çelësin
  (matricat, `H`, `[τ]₂`, `num_io`) në transkript. Testi i regresit:
  `the_number_of_public_inputs_is_part_of_the_circuit_identity`.
- **Vendimtari universal është `immutable`** te `ZenoLlullVerifier`: jepet në
  konstruktor dhe askush nuk e ndërron dot. Pronari kontrollon vetëm tarifën.
- **Kodime kanonike në `finalizeRecursive`.** Çdo skalar i `state` dhe i
  `cfProof` duhet të jetë nën modulin e vet, që një pretendim të ketë një
  kodim të vetëm në `decided`.
- **`zeno-evm-fixture` është mjet testimi, jo provues.** Përdor farë fikse,
  pra provat e tij nuk janë zero-knowledge. Provuesit e prodhimit thërrasin
  bibliotekën me gjenerator të rastësisë të sistemit.
- **Licenca në SDK.** Provuesi i SDK-së (`sdk_bindings::api::LicensedProver`)
  punon vetëm me licencë të vlefshme, të kontrolluar kundrejt çelësit publik
  të shitësit të ngulitur në ndërtim (`ZENO_VENDOR_PUBLIC_KEY` në kohën e
  kompilimit) dhe kundrejt orës së sistemit; kuota `max_steps` zbatohet në
  çdo hap. Një ndërtim pa atë variabël përdor çelësin e zhvillimit, pjesa
  private e të cilit është publike (`zeno-license issue --dev`), dhe e thotë
  këtë (`development_build`). **Ndërtimet e lëshimit duhet ta vendosin
  variablin.** Një kontroll në pajisjen e klientit mund të hiqet duke
  ndryshuar kodin: mbrojtja reale mbetet ligjore dhe te Cloud Prover.
- **Cloud Prover.** Licenca kontrollohet para se të lexohet trupi; madhësitë e
  deklaruara të qarkut kufizohen para çdo alokimi (`ZENO_MAX_WIRES`,
  `ZENO_MAX_CONSTRAINTS`); punët paralele kufizohen (`ZENO_MAX_JOBS`, 503
  kur është plot); faturimi bëhet brenda punës, pra edhe kur klienti
  shkëputet; nëse regjistri nuk shkruhet dot, nuk jepet asgjë. Regjistri
  dallon ndryshimet në mes, por jo prerjen e fundit apo rishkrimin e plotë:
  për këto duhet ruajtur diku tjetër `log_head` (nga `GET /v1/usage`).
  Një rresht i fundit pa `\n` (shkrim i ndërprerë nga një rrëzim, kurrë i
  konfirmuar) pritet në nisje me paralajmërim; çdo dëmtim tjetër e ndal
  nisjen. Kuota `max_steps` e licencës zbatohet për sesion (403). Prova e
  dhënë mbahet `ZENO_PROOF_RETENTION_SECS` (10 min): përsëritja e
  `finalize-snark` e kthen pa faturim të dytë (`x-zeno-repeated: true`).
  Sesionet e të njëjtit `.r1cs` ndajnë parametrat; një detyrë në sfond pastron
  çdo minutë sesionet joaktive, provat e skaduara dhe qarqet e papërdorura.
  `GET /metrics` (Prometheus, pa licencë, pa të dhëna klientësh) jep sesionet,
  punët dhe cache-t: ekspozoje vetëm në rrjetin e operatorit.
  **Mënyrat EVM** ndizen me `ZENO_PTAU_PATH` (ngarkohet dhe kontrollohet një
  herë në nisje, `Arc<Srs>` e përbashkët): `POST /v1/sessions?mode=universal`
  kthen `vk` dhe `open_session`; `POST /v1/finalize-evm?session=ID&onchain=0x…`
  kthen `verifyFoldedProofBatch` + `finalizeUniversal`. Me `mode=recursive`
  (2^20 fuqi), `finalize-evm` nis provën në sfond dhe kthen `202` derisa jep
  `finalizeRecursive` (`ZENO_MAX_RECURSIVE_JOBS`, parazgjedhje 1; rreth 2 GB
  secila). Faturimi: `proof` për B, `recursive-proof` për D. Sesionet janë në
  RAM: pas një rinisjeje klienti rifillon (ose vazhdon nga gjendja e ruajtur me
  SDK-në). Me disa kontejnerë, balancuesi duhet të mbajë afinitet sipas
  `session`.
  Shërbimi duhet vënë pas TLS-së, se licenca udhëton si bearer.
- **Formatet e serializuara** (prova `ZLP`+version, gjendja `ZLS`+version)
  kontrollohen me `core_r1cs::layout` para deserializimit: `ark-serialize`
  rezervon memorie sipas gjatësisë së deklaruar, kështu që pa këtë kontroll
  tetë bajte armiqësore e ndërprisnin procesin. Çdo format i ri që vjen nga
  jashtë duhet të kalojë nga e njëjta rrugë. Gjendja e provuesit përmban
  dëshmitë: është sekrete.
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

1. **Ulje e mëtejshme e gazit të `finalizeRecursive`** (sot 3.64 M: 3.01 M
   ekzekutim + 39 KB calldata, nga të cilat vendimtari i grupuar rreth 2.2 M). Dy
   provat universale janë bashkuar në një dhe matricat CycleFold vlerësohen
   nga struktura uniforme. Qarku mbyllës mbetet mbi 2^19 elemente jo-zero
   (782k, nga të cilat ~555k MSM-ja me bazë fikse, tashmë në kufirin e R1CS-së
   për bit), prandaj sistemi kërkon `.ptau 2^20`: vendim i marrë (ROADMAP,
   Optimizimi 2).
2. **Ulje e mëtejshme e gazit të `finalizeUniversal`**: reduktimi i pesë
   pretendimeve të vlerësimit në më pak pika.
3. **Publikimi**: paketa NPM, imazhi Docker, AAR dhe XCFramework ndërtohen në
   CI si artefakte, por nuk janë publikuar askund.
4. **Hyrje nga Noir dhe ONNX (zkML)**; vetëm Circom mbështetet.
5. **Avancimet opsionale të specifikimit**: CCS/HyperNova, SuperNova, SIMD.
6. **Optimizimi i MSM-së** (koha e hapit). MSM-ja me mbledhje afine të grupuara
   është ndërtuar (`llull-folder::msm`, feature `batch-affine-msm`, aktiv si
   parazgjedhje në `zeno-ivc`, `decider-zk`, `evm-verifier` dhe `sdk-bindings`,
   pra edhe në WASM, celular dhe `cloud-prover`): 1.31–1.57× për MSM-në, −10.6% për hapin IVC 2^16, −8% për
   provuesin e `finalizeRecursive`, +11 MiB memorie në hap. Përdoret vetëm te
   provuesi; kontrollet e angazhimeve mbeten me arkworks
   (`commit_reference`). SIMD (AVX-512 / NEON) nuk është bërë: kërkon `unsafe`
   dhe fitimi varet nga procesori.

## 9. Vendime të hapura për pronarin

1. **Finalizimi EVM i IVC-së rekursive** është ndërtuar (mënyra D), me të tre
   optimizimet e vendosura (3.64 M gas, `.ptau 2^20`). Mbetet vendimi nëse ia
   vlen investimi në uljen e mëtejshme të gazit të vendimtarit universal
   (pika 8.2).
2. **Mënyra Groth16 (C)**: e vendosur. Është jashtë prodhimit, pas
   `dev-groth16` dhe në kontratë më vete për zhvillim.
3. **Auditimi**: kur dhe nga kush, para çdo vendosjeje me vlerë reale.
4. **Publikimi dhe çelësat**: tokeni i organizatës `@zenollull` në NPM dhe
   çelësi privat i licencave të shitësit nuk ekzistojnë ende; mjeti
   `zeno-license keygen` e gjeneron të dytin. Çelësi publik përkatës duhet
   dhënë si `ZENO_VENDOR_PUBLIC_KEY` kur ndërtohen paketat e lëshimit.
5. **Zinxhiri i synuar**: mënyra D kushton 3.64 M gas, i njëjtë për çdo N.
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
cargo build --release -p evm-verifier -p zeno-evm -p cloud-prover -p zeno-license && node contracts/test/recursive.test.cjs
```

Të dy testet e EVM-së kalojnë edhe një qark të vërtetë Circom
(`crates/sdk-bindings/fixtures/step.circom`, dëshmi nga gjeneruesi i Circom-it)
deri te `finalizeUniversal` dhe `finalizeRecursive` (ky i fundit vetëm me
`ZENO_PTAU`), dy herë: nëpër `zeno-evm` dhe nëpër Cloud Prover-in e vërtetë
(`zenollull-cloud-prover` me `ZENO_PTAU_PATH`). Mënyra B nga SDK-ja WASM, si e
përdor një wallet, testohet te `sdk/wasm/test/onchain.test.cjs` (kërkon
`npm ci --prefix contracts`). Me dorë:

```bash
./target/release/zeno-evm key --r1cs step.r1cs --ptau ppot_0080_18.ptau --z0 3
```

```bash
./target/release/zeno-evm universal --r1cs step.r1cs --ptau ppot_0080_18.ptau --z0 3 --session 0x<id> --wtns step0.wtns step1.wtns
```

```bash
./target/release/zeno-evm recursive --r1cs step.r1cs --ptau ppot_0080_20.ptau --z0 3 --wtns step0.wtns step1.wtns
```

```bash
./target/release/zeno-evm trim-ptau --r1cs step.r1cs --ptau ppot_0080_18.ptau --out step.ptau
```

SDK-të:

```bash
export ZENO_TEST_LICENSE="$(cargo run -q --release -p zeno-license -- issue --dev --customer ci --plan enterprise --days 1)"
```

```bash
./scripts/build-wasm-sdk.sh && node sdk/wasm/test/ivc.test.cjs
```

Mënyra C (Groth16, vetëm zhvillim):

```bash
cargo build --release -p evm-verifier --features dev-groth16 && ZENO_DEV_GROTH16=1 node contracts/test/verifier.test.cjs
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
