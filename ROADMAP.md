# Roadmap — Zeno–Llull Nova IVC (Ideja 10)

Burimi: *Specifikimi Inxhinierik, Ideja 10 (Zeno–Llull Nova IVC)*. Çdo fazë
mbyllet vetëm kur kriteri i pranimit (KPI) verifikohet automatikisht në
GitHub Actions; vetëm pas CI të gjelbër kodi shkon në `main`.

Legjenda: ✅ e përfunduar dhe e verifikuar në CI · 🚧 në punë · ⏳ e planifikuar

## Faza 0 — Themelet ✅

- [x] Workspace Rust, `rust-toolchain.toml`, `no_std` për libraritë
- [x] CI: `fmt`, `clippy -D warnings`, teste, ndërtim `wasm32-unknown-unknown`, punë KPI

## Faza 1 — Bërthama algjebrike `llull-folder` (CLI) ✅

KPI: pas palosjes së `t = 100` hapave kalon `(AZ) ∘ (BZ) == u·CZ + E` me 0 gabime.

- [x] `core-r1cs`: matrica të rralla CSR, R1CS e relaksuar `Z = (W, x, u)` (ek. 1)
- [x] Urë nga `ark-relations` (çdo qark arkworks → CSR)
- [x] Angazhime Pedersen homomorfike, gjeneratorë transparentë me hash-to-curve (ek. 2)
- [x] Operatori i Llull-it: vektori i termave të kryqëzuar `T` (ek. 3–4)
- [x] Fiat–Shamir me sfungjer Poseidon mbi fushën bazë, sfidë 128-bit (ek. 5)
- [x] `nifs_prove` (punë lineare + 1 MSM) dhe `nifs_verify` (2 shumëzime skalare) (ek. 6–7)
- [x] Teste: KPI në Pallas, Vesta, BN254, Grumpkin; identiteti i ek. 8; teste negative
- [x] CLI `llull-folder fold --steps N --log-constraints K --curve pallas|bn254`

## Faza 2 — Qarku rekursiv 2-kurbësh `zeno-ivc` 🚧

KPI: koha e palosjes < 50 ms për hap (qark me 2^16 kufizime) — **ende e pa arritur**, shih matjet.

- [x] Gadget jo-nativ `c ≡ a + r·x (mod p)` me CRT (mod `n` dhe mod `2^128`), ~700 kufizime
- [x] Qarku i zgjeruar `F'`: `z_{i+1} = F(z_i)`, kontrolli i hash-it, `NIFS.Verify` me 2 shumëzime
      skalare, dalja `x = (u.x[1], H(vk, i+1, z_0, z_{i+1}, U'))`
- [x] Stepper IVC `ZenoAccumulator`: `prove_step` / `verify`, i përgjithshëm mbi ciklin
- [x] Ciklet Pallas/Vesta dhe BN254/Grumpkin, të testuara fund-më-fund
- [x] Teste negative: pretendime të falsifikuara, hap mashtrues, parametra të tjerë
- [x] Memorie konstante: RSS identike për 10, 100 dhe 400 hapa; e detyruar ≤ 512 MiB në CI
- [x] CLI `zeno-ivc prove --steps N --log-constraints K --cycle pasta|bn254`
- [ ] KPI i kohës: MSM me bazë fikse dhe tabela të parallogaritura, cache i `AZ, BZ, CZ`,
      sintezë pa mbingarkesën e `ark-relations`

## Faza 3 — Kompresuesi ZK dhe kontrata verifikuese (vendimtar me dy mënyra) ✅ / 🚧

KPI: prova finale < 4 KB — **arritur në Mënyrën B (544 bajt)**; Mënyra A ~10 KB.
Kosto EVM < 300k gas — **arritur për çdo hap (~74k)**; vendimi final në zinxhir kushton ~456k një herë për sesion.

Maskimi zero-knowledge (i përbashkët):

- [x] Palosja e plotë relaksuar-me-relaksuar (`E ← E1 + r·T + r²·E2`, `u ← u1 + r·u2`)
- [x] Palosje me një çift të relaksuar të rastësishëm (`sample_relaxed`): dëshmia `W' = W + r·W_rand` është uniforme

Mënyra A — 100% transparente (off-chain, celular, portofole), mbi çdo cikël:

- [x] SNARK pa Trusted Setup dhe pa FFT: dy sum-check (stil Spartan) + IPA mbi vetë gjeneratorët Pedersen
- [x] `CompressedIvcProof`: 1.46 MB → ~10 KB, e pavarur nga numri i hapave; kufi 16 KiB në CI
- [x] CLI `zeno-decider`; SDK WASM dhe Cloud Prover nxjerrin këtë provë

Mënyra B — EVM (`contracts/ZenoLlullVerifier.sol`, BN254):

- [x] Palosje në zinxhir: `verifyFoldedProof(bytes, uint256[])` me 2 `ecMul` + 2 `ecAdd`, sfidë Keccak,
      sesione, zinxhirim `z_out → z_in`, `protocolFee`
- [x] Angazhime KZG mbi SRS universale (`evm-verifier::kzg`), homomorfike si Pedersen
- [x] Qarku vendimtar Groth16 (`decider_circuit`): R1CS e relaksuar + `d = Poseidon(W, E)` + `W(c)`, `E(c)`,
      me `c = keccak(akumulator, d)`. Digjesti `d` e fikson dëshminë brenda Groth16 **para** se të dihet
      pika `c`; pa të, provuesi mund të zëvendësonte dëshminë me një tjetër që përputhet vetëm në `c`
      (e çarë e versionit të parë, e mbyllur me test regresi)
- [x] `finalizeWithProof`: palosja maskuese + 2 hapje KZG të grupuara + Groth16 në një thirrje
      çiftëzimi me 6 çifte; sesioni shënohet `decided`
- [x] Test në EVM lokale me precompile reale: akumulatori në zinxhir = ai i provuesit, 16 falsifikime
      të refuzuara, çelës i panjohur i refuzuar, matje gazi
- [x] `finalize` (pa provë në zinxhir) + `verify_final` jashtë zinxhirit mbetet për mënyrën transparente
- [x] `Srs::from_ptau`: ngarkon SRS nga skedarët `.ptau` të ceremonive publike (Perpetual Powers of
      Tau / Hermez) dhe verifikon strukturën (pika në kurbë, fuqi të njëpasnjëshme me çiftëzim);
      testi EVM përdor një skedar real të këtij formati
- [x] **Vendimtar universal — zero setup për qark** (`evm-verifier::universal`, `ZenoUniversalDecider.sol`):
  - matricat `A, B, C` angazhohen një herë, në mënyrë deterministe dhe publike, nga `.ptau`
    (`CircuitKey::preprocess`: `row, col, val_A, val_B, val_C, count_row, count_col`); pa sekrete,
    kushdo i rillogarit
  - argument stil Spartan: sum-check i jashtëm dhe i brendshëm, pastaj vlerësimi i matricave pa i
    lexuar ato — produkt `Σ val·e_row·e_col` me kërkime LogUp që vërtetojnë `e_row = eq(r_x, row)`
    dhe `e_col = eq(r_y, col)`
  - hapje shumëlineare HyperKZG mbi të njëjtat angazhime KZG të palosjes; 5 hapje, një çiftëzim
  - transkript Keccak identik në Rust dhe Solidity; `finalizeUniversal` e shënon sesionin `decided`
  - teste: ~60 falsifikime në Rust; në EVM çdo fjalë e provës (232) dhe e çelësit refuzohet
  - matje në EVM (gaz i `finalizeUniversal`, përfshirë palosjen maskuese dhe calldata):

    | Kufizime të qarkut | Gaz | Prova |
    |---|---|---|
    | 16 | ~0.82 M | 6.7 KB |
    | 256 | ~1.18 M | 11.6 KB |
    | 4096 | ~1.53 M | 16.6 KB |
    | 65 536 (mbi `.ptau` publike PPoT, 2^18 fuqi) | ~1.89 M | 21.6 KB |

    Rritja është logaritmike: rreth 89k gas dhe 1.25 KB për çdo dyfishim të qarkut. Provuesi për
    2^16 kufizime: ~10 s gjithsej (ngarkim + validim i `.ptau`, parapërpunim, provë)
  - optimizime: transkript dhe kopjime në assembly (`mcopy`); **hapje e bashkuar** — të pesë
    pretendimet hapen në të njëjtat tre pika `r, −r, r²`, pra 3 prova KZG gjithsej në vend të 15
  - **identitet pa leje i qarkut**: sesioni hapet me `vk = keccak256(çelësi i qarkut)` dhe vetëm ai
    çelës mund ta vendosë; nuk ka regjistër, pronar apo mundësi "zënieje". `announceCircuit` është
    vetëm publikim informativ. Kushdo e rillogarit identitetin nga qarku dhe `.ptau`
  - CI shkarkon `.ptau` publike (me cache dhe kontroll SHA-256) dhe mat 2^16 në çdo ekzekutim
- [ ] Ulje e mëtejshme e gazit: reduktimi i pesë pretendimeve në më pak pika shumëlineare
- [ ] Mënyra Groth16 (`finalizeWithProof`) mbetet **vetëm për zhvillim**: çelësat janë specifikë për
      qarkun dhe `DeciderKeys::insecure_for_testing` i gjeneron me një palë të vetme
- [ ] `finalizeWithProof` < 300k gas: 6 çifte kushtojnë vetë ~249k (dy hapjet KZG janë tashmë të
      grupuara në një kontroll)
- [x] `verifyFoldedProofBatch`: shumë hapa në një transaksion (ruajtja lexohet dhe shkruhet një herë):
      ~22.9k gas për hap (100 hapa = 2.29 M gas), akumulator identik me palosjen një nga një
- [ ] Finalizimi në EVM i IVC-së **rekursive** off-chain (një provë për N hapa, e pavarur nga N) 🚧.
      Pengesa: EVM nuk ka precompile për Grumpkin, dhe hapja e një angazhimi Pedersen me `M` elemente
      kërkon `M` shumëzime skalare. Rruga: **CycleFold** (akumulatori sekondar zbret nga ~11k në
      ~1.3k elemente) + **angazhime Hyrax për çdo rresht** (hapja kushton `rreshta + kolona` në vend të
      `M`) + një qark mbyllës BN254 i vendosur me `finalizeUniversal`.
  - [x] **Hapi 1 — qarku CycleFold** (`zeno-ivc::cyclefold::circuit`): `out = p1 + [r]·p2` mbi fushën
        bazë të BN254, hyrje publike `(r, p1, p2, out)`, identiteti si `(0, 0)`, kontroll që pikat janë
        në kurbë: **936 kufizime** (1 344 me gadget-et e arkworks). Teste: identiteti në çdo pozicion, dyfishim në
        mbledhjen e fundit, dalje e falsifikuar, pika jashtë kurbës, çdo hyrje publike e lidhur
  - [x] **Hapi 2 — stepper-i CycleFold** (`cyclefold::{augmented, ivc, hyrax}`): qarku primar palos
        `u` dhe `x` të instancës BN254 në mënyrë native dhe ia delegon `W' = W + r·W_new` dhe
        `E' = E + r·T` dy instancave CycleFold, që paloset në një akumulator në Grumpkin me angazhime
        për çdo rresht. Një transkript i vetëm Poseidon për hap jep `r`, `r_1`, `r_2`. Çelësi primar
        jepet nga thirrësi: hash-to-curve ose fuqitë e një `.ptau` (KZG), të dyja të testuara. Teste
        fund-më-fund në BN254/Grumpkin dhe Pallas/Vesta, falsifikime të gjendjes dhe të të dy
        akumulatorëve, dhe një palosje e deleguar e gabuar që e bën akumulatorin të pakënaqshëm
  - [x] `mul_add_mod` zgjedh vetë numrin e limbeve (2 → 3) kur operandi është një koordinatë e plotë
        254-bitëshe; për përdorimet ekzistuese kufizimet mbeten të njëjta (test mutacioni për të dyja)
  - [x] **Gadget-e me peshë të ulët** (`zeno-ivc::gadgets`), ku çdo ndërmjetës është variabël:
    - `ec`: pika afine (identiteti `(0, 0)`, kodim unik), mbledhje e plotë (~20 kufizime, çdo rast:
      identitet, të barabarta, të kundërta, `x = 0`) dhe `A + [r]·B` me dyfishim-e-mbledhje
      Eisenträger–Lauter–Montgomery dhe shifra ±1. Sfidat kanë formën `r = 2^128 + 2t + 1` me `t`
      127-bitësh: çdo shumëfish i ndërmjetëm është `[k]B` me `k` tek dhe `3 ≤ k < 2^129`, prandaj
      formulat jo të plota nuk kanë **asnjë** rast përjashtimor për asnjë provues (jo vetëm me
      probabilitet të vogël). `A + [r]·B`: **933 kufizime / 4.2k elemente jo-zero** kundrejt
      1 329 / 70.4k me arkworks. Teste: çdo kombinim rastesh, krahasim me aritmetikën native,
      mutacion (asnjë dëshmi e lirë)
    - `poseidon`: i njëjti funksion si `PoseidonSponge` native i arkworks (testuar në çdo radhë
      thithje/shtrydhje), me gjendjen të rialokuar çdo 8 ronde të pjesshme: **2.6× më pak elemente
      jo-zero** për 13% më shumë kufizime
  - Kompromisi i Hyrax-it, i matur (C kolona; qarku CycleFold tani **936 kufizime**, rreshta =
    ⌈936 / C⌉ për `W` dhe për `E`; qarku primar me hap aplikacioni minimal):

    | C | rreshta W/E | kufizime për hap | elemente jo-zero | para gadget-eve |
    |---|---|---|---|---|
    | 1024 (Pedersen i zakonshëm) | 1/1 | 32 400 | 0.24 M | 38 744 / 1.07 M |
    | 512 | 2/2 | 37 313 | 0.28 M | 45 074 / 1.39 M |
    | 256 | 4/4 | 47 139 | 0.34 M | 64 064 / 2.36 M |
    | **128 (zgjedhja)** | **8/8** | **66 791** | **0.47 M** | 95 714 / 3.97 M |
    | 64 | 15/15 | 101 182 | 0.69 M | 159 014 / 7.21 M |

    Çdo rresht shton ~2.5k kufizime në çdo hap. Akumulatori primar me C = 128 vendoset me
    `finalizeUniversal` mbi `.ptau` 2^20 (max(m, 2n, jo-zero) ≈ 2^19 për një hap aplikacioni të vogël)
  - [ ] **Hapi 3 — qarku mbyllës.** Plani, i korrigjuar pas matjeve:
    - Hyrax jep vetëm *vlerësime* `W̃(r_y)`, `Ẽ(r_x)`. Që akumulatori CycleFold është i kënaqshëm
      vërtetohet me një sum-check (stil Spartan) mbi `Fq`, që është jo-native në BN254. Sum-check-u
      dhe vlerësimi i matricave të qarkut CycleFold (fiks për gjithë sistemin) bëhen **në Solidity**,
      ku `Fq` është native (`mulmod`); qarku mbyllës BN254 bën vetëm hapjen Hyrax
      (`Σ_i L_i·C_i = Σ_j w'_j·G_j`: 2R shumëzime me bazë të ndryshueshme + C me bazë fikse) dhe
      hash-in e gjendjes
    - matur me gadget-et e arkworks (skalarë 254-bitësh): një shumëzim me bazë të ndryshueshme
      kushton **2 594** kufizime, një me bazë fikse **1 545**. Bërthama e hapjes Hyrax del
      **208k** kufizime / **11.7 M** elemente jo-zero për C = 64 (R = 21) dhe **255k / 6.8 M** për
      C = 128 (R = 11). Rreth 20–30× më pak kufizime se 4–8 M, por jo brenda `.ptau` 2^18
    - vendimtari universal kërkon fuqi ≥ max(m, 2n, elemente jo-zero), pra **dendësia** vendos:
      2^18 mban qarqe deri në ~2^16 kufizime vetëm nëse matricat janë të rralla. Gadget-et e
      arkworks futen të plota në kombinime lineare (deri në ~56 elemente për kufizim te shuma e
      pikave; ~23 te qarku primar, kryesisht Poseidon dhe paketimi i biteve)
    - vendim: C = 128 (8 + 8 rreshta), `.ptau` 2^20 në CI me `actions/cache`, një provë e vetme
      për `finalizeUniversal`. Mbetet: MSM me bazë fikse (128 baza) dhe MSM me dyfishim të
      përbashkët (16 rreshta) me peshë të ulët, qarku mbyllës dhe matja e tij (synimi ~140k
      kufizime, ~0.7 M elemente jo-zero)
  - [ ] Hapi 4 — kontrata (`finalizeRecursive`), test në EVM lokale dhe matja e gazit

## Faza 4 — Paketa SDK për treg `sdk-bindings` 🚧

KPI: memorie maksimale ≤ 512 MB në shfletues/celular — **arritur në WASM** (≈161 MiB, e detyruar në CI).

- [x] Hyrje nga Circom: analizues `.r1cs` / `.wtns`, `R1csStep` (çdo R1CS i jashtëm si funksion hapi)
- [x] `CircomIvc`: IVC mbi BN254/Grumpkin me dëshmi nga gjeneruesi i Circom-it
- [x] Paketa NPM `@zenollull/wasm-sdk` (wasm-bindgen, tipe TypeScript, Node.js + shfletues)
- [x] Test fund-më-fund në Node.js në CI: 25 hapa, provë ZK, verifikues i pavarur, kufi memorie
- [x] `zeno-license`: `EnterpriseLicenseKey` i nënshkruar me Ed25519, verifikim offline vetëm me
      çelësin publik; mjet shitësi `zeno-license keygen | issue | verify`; `verifyLicense` në WASM
- [x] `ZenoLlull-Cloud-Prover` (axum): `POST /v1/sessions`, `POST /v1/fold-step`,
      `POST /v1/finalize-snark`, `GET /v1/usage`; licenca është kredenciali i API-së (pa bazë çelësash)
- [x] Matje pay-per-proof për klient me regjistër të lidhur me hash (SHA-256), që zbulon çdo
      fshirje ose ndryshim; rikthehet pas rinisjes
- [x] `Dockerfile` + test tymi në CI kundrejt kontejnerit
- [ ] Publikimi në NPM / regjistër kontejnerësh (kërkon token të organizatës)
- [x] SDK native me UniFFI (`crates/mobile-ffi`): një API Rust → lidhje Swift, Kotlin dhe Python;
      test fund-më-fund në Python në CI (~93 ms / hap me shumë fije), kontroll tipesh për Swift
- [x] Paketimi për pajisje: `scripts/build-android-aar.sh` (AAR me arm64-v8a, armeabi-v7a, x86_64 +
      lidhjet Kotlin, Gradle) dhe `scripts/build-ios-xcframework.sh` (XCFramework pajisje + simulator +
      Swift), të dyja të ndërtuara në CI
- [x] Shumë-fije në WASM (`wasm-bindgen-rayon`, varianti `@zenollull/wasm-sdk/threads`): ~350–390 ms / hap
      me 4 fije në Chromium (nga ~0.9 s), finalizimi ~6 s (nga ~18 s); test në Chromium pa kokë në CI
- [ ] Hyrje nga Noir dhe ONNX (zkML)

## Avancime opsionale (spec §4)

- [ ] CCS / HyperNova me Sum-Check
- [ ] SuperNova (IVC jo-uniforme) për zkVM
- [ ] SIMD (AVX-512 / NEON) për SpMV dhe MSM

## Matje aktuale (4 vCPU, Pallas/Vesta)

| Metrika | Vlera |
|---|---|
| Mbingarkesa e rekursionit (qarku primar) | ~11 200 kufizime |
| Qarku sekondar | ~11 200 kufizime |
| Faza 1 — vetëm `nifs_prove`, 2^16 kufizime | ~148 ms / hap |
| Faza 1 — `nifs_verify` | ~0.5 ms / hap |
| Faza 2 — hap i plotë IVC, hap me 2^8 kufizime | ~135 ms |
| Faza 2 — hap i plotë IVC, hap me 2^16 kufizime | ~415 ms |
| Verifikimi IVC | ~125–370 ms, i pavarur nga numri i hapave |
| RSS maksimale (2^16, e pavarur nga `t`) | ~225 MiB |
| WASM (Node.js, 1 fije, qark Circom) | ~0.9–1.3 s / hap, ~161 MiB memorie |
| WASM me shumë fije (Chromium, 4 fije, qark Circom) | ~350–390 ms / hap, ~170 MiB |
| SDK native (Python/Swift/Kotlin, 4 fije, qark Circom) | ~93 ms / hap |
| Shkallëzimi me fije (hap 2^16) | 946 ms (1) → 553 ms (2) → 307 ms (4) |
| `verifyFoldedProof` në EVM | ~74k gas (198k hapi i parë) |
| `verifyFoldedProofBatch` në EVM | ~22.9k gas për hap (100 hapa në një transaksion) |
| `finalizeWithProof` në EVM (Groth16, vetëm zhvillim) | ~456k gas, provë 544 bajt |
| `finalizeUniversal` në EVM (zero setup) | ~0.82 M gas / 6.7 KB (16 kufizime) → ~1.89 M / 21.6 KB (65 536) |
| Prova ZK e kompresuar | ~9.8–10.8 KB (2^10–2^16 kufizime për hap) |
| Kompresimi (një herë, në fund) | ~1.4 s në 2^10, ~5.4 s në 2^16; ~21 s në WASM |
| Verifikimi i provës së kompresuar | ~0.2 s në 2^10, ~0.8 s në 2^16 |

Koha dominohet nga dy MSM-të për hap (`comm_W` dhe `comm_T`) mbi dëshmi të
dendura; KPI-ja < 50 ms/hap në 2^16 **nuk** arrihet në 4 vCPU me MSM-në
aktuale. Shifra "4 000 kufizime për hap" e specifikimit gjithashtu nuk arrihet:
mbingarkesa reale e matur është ~11 200 kufizime.

Ndarja e 11 217 kufizimeve të qarkut primar: hash-et Poseidon ~6 050 (54%), dy shumëzimet
skalare ~2 370 (~9 kufizime/bit), aritmetika jo-native ~1 450, alokimet/bitët ~1 300.
