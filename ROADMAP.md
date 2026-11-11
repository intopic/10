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

KPI: prova finale < 4 KB; kosto EVM < 300k gas — **ende e pa arritur**.

- [x] Palosja e plotë relaksuar-me-relaksuar (`E ← E1 + r·T + r²·E2`, `u ← u1 + r·u2`)
- [x] Maskimi zero-knowledge: palosje me një çift të relaksuar të rastësishëm
      (`sample_relaxed`), dëshmia e hapur `W' = W + r·W_rand` është uniforme
- [x] `ZkIvcProof::prove / verify`, serializim, teste negative
- [ ] Kompresim i shkurtër: SNARK mbi akumulatorin (Spartan + IPA, pa Trusted Setup).
      Prova aktuale ZK është lineare në madhësinë e qarkut (MB, jo KB)
- [ ] `contracts/ZenoLlullVerifier.sol` me `verifyFoldedProof` dhe `protocolFee`.
      < 300k gas kërkon mbështjellje Groth16/PlonK (me Trusted Setup) mbi BN254
- [ ] Teste Foundry me matje gazi në CI

## Faza 4 — Paketa SDK për treg `sdk-bindings` ⏳

KPI: memorie maksimale ≤ 512 MB në shfletues/celular.

- [ ] Paketa NPM `@zenollull/wasm-sdk` (wasm-bindgen + tipe TypeScript)
- [ ] Lidhje FFI: Swift (XCFramework), Kotlin (AAR/JNI), Python (zkML)
- [ ] `ZenoLlull-Cloud-Prover`: `POST /v1/fold-step`, `POST /v1/finalize-snark`, Docker
- [ ] Matja e përdorimit dhe çelësi i licencës (`EnterpriseLicenseKey`)
- [ ] Pipeline release CI/CD për tri paketat A / B / C

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

Koha dominohet nga dy MSM-të për hap (`comm_W` dhe `comm_T`) mbi dëshmi të
dendura; KPI-ja < 50 ms/hap në 2^16 **nuk** arrihet në 4 vCPU me MSM-në
aktuale. Shifra "4 000 kufizime për hap" e specifikimit gjithashtu nuk arrihet:
mbingarkesa reale e matur është ~11 200 kufizime.
