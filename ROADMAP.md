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

## Faza 3 — Kompresuesi ZK dhe kontrata verifikuese `decider-zk` 🚧

KPI: prova finale < 4 KB — **e pa arritur** (~10 KB). Kosto EVM < 300k gas — **arritur për palosjen
në zinxhir** (~75k gas/hap); vendimtari i shkurtër verifikohet jashtë zinxhirit.

- [x] Palosja e plotë relaksuar-me-relaksuar (`E ← E1 + r·T + r²·E2`, `u ← u1 + r·u2`)
- [x] Maskimi zero-knowledge: palosje me një çift të relaksuar të rastësishëm
      (`sample_relaxed`), dëshmia e hapur `W' = W + r·W_rand` është uniforme
- [x] `ZkIvcProof::prove / verify` (varianti i pakompresuar), serializim, teste negative
- [x] Kompresues i shkurtër pa Trusted Setup dhe pa FFT: dy sum-check (stil Spartan) +
      argument i produktit të brendshëm (IPA) mbi vetë gjeneratorët Pedersen të palosjes
- [x] `CompressedIvcProof`: 1.46 MB → ~10 KB, e pavarur nga numri i hapave, logaritmike
      në madhësinë e qarkut; 16 teste mutacioni refuzohen; kufi 16 KiB i detyruar në CI
- [x] CLI `zeno-decider --steps N --log-constraints K --cycle pasta|bn254`
- [x] `contracts/ZenoLlullVerifier.sol`: verifikues i palosjes në zinxhir (BN254, precompile
      `ecMul`/`ecAdd`), `verifyFoldedProof(bytes, uint256[])`, sesione, zinxhirim i gjendjes
      `z_out → z_in`, `finalize` me maskim ZK, `protocolFee` me tërheqje nga pronari
- [x] `crates/evm-verifier`: transkript Keccak identik me kontratën, kodim ABI, `OnChainFolder`,
      vendimtar jashtë zinxhirit `verify_final` kundrejt akumulatorit në zinxhir
- [x] Test në EVM lokale (precompile reale BN254) në CI: akumulatori në zinxhir = ai i provuesit,
      ~75k gas për hap (199k hapi i parë), kufi 300k i detyruar, kontroll aksesi dhe tarife
- [ ] Vendimtar **në zinxhir**: IPA kërkon MSM mbi mijëra pika dhe nuk verifikohet dot në EVM;
      kërkon akumulim në një kurbë (CycleFold) + KZG + mbështjellje Groth16 (Trusted Setup).
      Deri atëherë vlefshmëria e dëshmisë së akumuluar verifikohet jashtë zinxhirit
- [ ] Prova < 4 KB (e njëjta rrugë: CycleFold + KZG)

## Faza 4 — Paketa SDK për treg `sdk-bindings` 🚧

KPI: memorie maksimale ≤ 512 MB në shfletues/celular — **arritur në WASM** (≈161 MiB, e detyruar në CI).

- [x] Hyrje nga Circom: analizues `.r1cs` / `.wtns`, `R1csStep` (çdo R1CS i jashtëm si funksion hapi)
- [x] `CircomIvc`: IVC mbi BN254/Grumpkin me dëshmi nga gjeneruesi i Circom-it
- [x] Paketa NPM `@zenollull/wasm-sdk` (wasm-bindgen, tipe TypeScript, Node.js + shfletues)
- [x] Test fund-më-fund në Node.js në CI: 25 hapa, provë ZK, verifikues i pavarur, kufi memorie
- [ ] Publikimi në NPM (kërkon llogari/token të organizatës `@zenollull`)
- [ ] Lidhje FFI: Swift (XCFramework), Kotlin (AAR/JNI), Python (zkML)
- [ ] `ZenoLlull-Cloud-Prover`: `POST /v1/fold-step`, `POST /v1/finalize-snark`, Docker
- [ ] Matja e përdorimit dhe çelësi i licencës (`EnterpriseLicenseKey`) — kërkon çelës nënshkrimi të shitësit
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
| WASM (Node.js, 1 fije, qark Circom) | ~1.3 s / hap, ~161 MiB memorie |
| `verifyFoldedProof` në EVM | ~75k gas (199k hapi i parë), `finalize` ~87k |
| Prova ZK e kompresuar | ~9.8–10.8 KB (2^10–2^16 kufizime për hap) |
| Kompresimi (një herë, në fund) | ~1.4 s në 2^10, ~5.4 s në 2^16; ~21 s në WASM |
| Verifikimi i provës së kompresuar | ~0.2 s në 2^10, ~0.8 s në 2^16 |

Koha dominohet nga dy MSM-të për hap (`comm_W` dhe `comm_T`) mbi dëshmi të
dendura; KPI-ja < 50 ms/hap në 2^16 **nuk** arrihet në 4 vCPU me MSM-në
aktuale. Shifra "4 000 kufizime për hap" e specifikimit gjithashtu nuk arrihet:
mbingarkesa reale e matur është ~11 200 kufizime.
