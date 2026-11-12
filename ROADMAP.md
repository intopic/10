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
- [ ] Çelësat Groth16 të vendimtarit janë **specifikë për qarkun e aplikacionit** (qarku vendimtar
      përmban matricat `A, B, C`): duhet ceremoni faze 2 për çdo qark, ose zëvendësim me një
      sistem me setup universal (PlonK/HyperKZG) që të mos kërkohet asgjë nga klienti
- [ ] `finalizeWithProof` < 300k gas: 6 çifte kushtojnë vetë ~249k; kërkon vendimtar pa Groth16
- [ ] Mënyra B për IVC-në rekursive off-chain (tani zinxhiri është vetë verifikuesi i palosjes)

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
- [ ] Paketimi për pajisje: XCFramework (kërkon makinë macOS) dhe AAR (kërkon Android NDK)
- [ ] Shumë-fije në WASM (aktualisht një fije: ~1.3 s / hap)
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
| SDK native (Python/Swift/Kotlin, 4 fije, qark Circom) | ~93 ms / hap |
| Shkallëzimi me fije (hap 2^16) | 946 ms (1) → 553 ms (2) → 307 ms (4) |
| `verifyFoldedProof` në EVM | ~74k gas (198k hapi i parë) |
| `finalizeWithProof` në EVM (një herë) | ~456k gas, provë 544 bajt |
| Prova ZK e kompresuar | ~9.8–10.8 KB (2^10–2^16 kufizime për hap) |
| Kompresimi (një herë, në fund) | ~1.4 s në 2^10, ~5.4 s në 2^16; ~21 s në WASM |
| Verifikimi i provës së kompresuar | ~0.2 s në 2^10, ~0.8 s në 2^16 |

Koha dominohet nga dy MSM-të për hap (`comm_W` dhe `comm_T`) mbi dëshmi të
dendura; KPI-ja < 50 ms/hap në 2^16 **nuk** arrihet në 4 vCPU me MSM-në
aktuale. Shifra "4 000 kufizime për hap" e specifikimit gjithashtu nuk arrihet:
mbingarkesa reale e matur është ~11 200 kufizime.

Ndarja e 11 217 kufizimeve të qarkut primar: hash-et Poseidon ~6 050 (54%), dy shumëzimet
skalare ~2 370 (~9 kufizime/bit), aritmetika jo-native ~1 450, alokimet/bitët ~1 300.
