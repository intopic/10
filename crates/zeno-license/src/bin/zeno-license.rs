//! Vendor tool for license keys.

use std::{process::ExitCode, time::SystemTime};
use zeno_license::{
    generate_keypair, issue, key_to_hex, parse_key_hex, public_key, verify, Claims,
};

const USAGE: &str = "\
zeno-license — issue and check Zeno–Llull license keys

USAGE:
    zeno-license keygen
    zeno-license issue  --customer NAME --plan PLAN --days N     (private key in ZENO_LICENSE_PRIVATE_KEY)
    zeno-license verify --key TOKEN --public-key HEX

Keep the private key secret; ship only the public key.
";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flag(args: &[String], name: &str) -> Result<String, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .ok_or(format!("missing {name}"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let (private, public) = generate_keypair();
            println!("ZENO_LICENSE_PRIVATE_KEY={}", key_to_hex(&private));
            println!("ZENO_LICENSE_PUBLIC_KEY={}", key_to_hex(&public));
            Ok(())
        }
        Some("issue") => {
            let private = std::env::var("ZENO_LICENSE_PRIVATE_KEY")
                .map_err(|_| "ZENO_LICENSE_PRIVATE_KEY is not set".to_string())?;
            let private = parse_key_hex(&private).map_err(|e| e.to_string())?;
            let days: u64 = flag(args, "--days")?
                .parse()
                .map_err(|_| "--days: not a number")?;
            let claims = Claims {
                customer: flag(args, "--customer")?,
                plan: flag(args, "--plan")?,
                expires_at: now() + days * 86_400,
            };
            println!("{}", issue(&private, &claims).map_err(|e| e.to_string())?);
            eprintln!("public key: {}", key_to_hex(&public_key(&private)));
            Ok(())
        }
        Some("verify") => {
            let public = parse_key_hex(&flag(args, "--public-key")?).map_err(|e| e.to_string())?;
            let claims =
                verify(&flag(args, "--key")?, &public, now()).map_err(|e| e.to_string())?;
            println!(
                "valid: customer={} plan={} expires_at={}",
                claims.customer, claims.plan, claims.expires_at
            );
            Ok(())
        }
        _ => Err(String::new()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) if msg.is_empty() => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
