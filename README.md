# Zeno–Llull Nova IVC

Motor palosjeje rekursive (*Incrementally Verifiable Computation*) që kompreson
një numër arbitrar hapash llogaritjeje në një akumulator me madhësi konstante
`O(1)` — pa FFT dhe pa Trusted Setup, me vetëm 2 shumëzime skalare në kurbën
eliptike për çdo hap verifikimi.

Gjendja e projektit dhe plani: shih [ROADMAP.md](ROADMAP.md).

## Struktura

| Crate | Përgjegjësia |
|---|---|
| `crates/core-r1cs` | Matricat CSR `A, B, C`, R1CS e relaksuar, instanca `U` dhe dëshmia `W` |
| `crates/llull-folder` | Pedersen, vektori `T` i Llull-it, transkripti Poseidon, `nifs_prove` / `nifs_verify`, CLI |
| `crates/zeno-ivc` | Qarku rekursiv `F'`, aritmetika jo-native, stepper IVC mbi ciklin 2-kurbësh, CLI |

## Përdorimi

```bash
cargo test --workspace
```

```bash
cargo run --release -p llull-folder -- fold --steps 100 --log-constraints 16 --curve pallas
```

IVC e plotë rekursive (çdo hap verifikon palosjen e hapit të mëparshëm):

```bash
cargo run --release -p zeno-ivc -- prove --steps 100 --log-constraints 12 --cycle pasta
```

Ndërtimi për shfletues/celular:

```bash
cargo build --release --target wasm32-unknown-unknown -p llull-folder -p zeno-ivc --no-default-features --lib
```

## Matematika në një rresht

`(A·Z) ∘ (B·Z) = u·(C·Z) + E`, me `Z = (W, x, u)`. Palosja e akumulatorit
`(U1, W1)` me hapin e ri `(U2, W2)` nën sfidën `r`:

```text
T      = AZ1∘BZ2 + AZ2∘BZ1 − u1·CZ2 − u2·CZ1
W      ← W1 + r·W2            E      ← E1 + r·T
comm_W ← comm_W1 + r·comm_W2  comm_E ← comm_E1 + r·comm_T      u ← u1 + r
```
