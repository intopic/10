//! Generates the Swift / Kotlin / Python sources from the compiled library:
//! `uniffi-bindgen generate --library <libzenollull> --language <lang> --out-dir <dir>`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
