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

## Faza 2 — Qarku rekursiv 2-kurbësh `zeno-ivc` ⏳

KPI: koha e palosjes < 50 ms për hap (qark me 2^16 kufizime).

- [ ] Gadget-ët në qark: sfungjer Poseidon, pikë kurbe, palosja e instancës (`NIFS.Verify`)
- [ ] Qarku i zgjeruar `F'`: `z_t = F(z_{t-1})`, kontrolli i hash-it, dalja `x_t = H(vk, t, z_0, z_t, U_t)`
- [ ] Cikli Pallas/Vesta dhe BN254/Grumpkin; `IVCProof` me verifikim të plotë
- [ ] Optimizim i provuesit drejt KPI: MSM për `T`, SpMV paralele, shmangie alokimesh
- [ ] Akumulator me memorie konstante: teste që RSS nuk rritet me `t`

## Faza 3 — Kompresuesi ZK dhe kontrata verifikuese `decider-zk` ⏳

KPI: prova finale < 4 KB; kosto EVM < 300k gas.

- [ ] Maskimi zero-knowledge i akumulatorit para kompresimit
- [ ] SNARK përfundimtar mbi akumulatorin `(U_t, W_t)`
- [ ] `contracts/ZenoLlullVerifier.sol` me `verifyFoldedProof` dhe `protocolFee`
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

## Matje aktuale (Faza 1, 4 bërthama CPU, Pallas, 2^16 kufizime)

| Metrika | Vlera |
|---|---|
| Provuesi | ~148 ms / hap (dominohet nga MSM e `T`) |
| Verifikuesi | ~0.5 ms / hap |
| Instanca `U` | 170 bajt, konstante në `t` |
| RSS maksimale pas 100 hapash | ~162 MiB |

Shënim: KPI-ja < 50 ms/hap i përket Fazës 2 dhe ende **nuk** është arritur.
