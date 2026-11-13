//! The API shared by every binding (WebAssembly, Swift, Kotlin, Python): the
//! licensed prover, the statement of a proof and the conversions of states.
//! The bindings only wrap these types in what their generator needs.

use crate::{circom::SdkError, CircomIvc, Fr, Proof};
use ark_ff::PrimeField;
use std::str::FromStr;
use zeno_license::Claims;

/// The public statement proven by a proof: `zi = F^steps(z0)`, with the
/// states as decimal strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub steps: u64,
    pub z0: Vec<String>,
    pub zi: Vec<String>,
}

/// What a license key grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseInfo {
    pub customer: String,
    pub plan: String,
    /// Expiry as Unix time in seconds.
    pub expires_at: u64,
    /// Largest number of steps one prover may fold (`None`: unlimited).
    pub max_steps: Option<u64>,
    /// Whether this build checks licenses against the public development
    /// key instead of a vendor key (see `zeno_license`).
    pub development_build: bool,
}

/// Parses a state given as decimal strings.
pub fn parse_state(z: &[String]) -> Result<Vec<Fr>, SdkError> {
    z.iter()
        .map(|s| Fr::from_str(s).map_err(|_| SdkError::InvalidFieldElement))
        .collect()
}

/// A state as decimal strings.
pub fn state_strings(z: &[Fr]) -> Vec<String> {
    z.iter().map(|f| f.into_bigint().to_string()).collect()
}

/// The statement of a decoded proof.
pub fn statement_of(proof: &Proof) -> Statement {
    Statement {
        steps: proof.statement.i,
        z0: state_strings(&proof.statement.z0),
        zi: state_strings(&proof.statement.zi),
    }
}

/// The current Unix time in seconds.
pub fn unix_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn claims(license: &str) -> Result<Claims, SdkError> {
    zeno_license::verify_for_this_build(license, unix_now())
        .map_err(|e| SdkError::License(e.to_string()))
}

/// Verifies a license key against the vendor key compiled into this build,
/// at the current time.
pub fn check_license(license: &str) -> Result<LicenseInfo, SdkError> {
    let c = claims(license)?;
    Ok(LicenseInfo {
        customer: c.customer,
        plan: c.plan,
        expires_at: c.expires_at,
        max_steps: c.max_steps,
        development_build: zeno_license::vendor_key_is_development(),
    })
}

/// The SDK's prover: a [`CircomIvc`] that only runs under a valid license.
/// The license is checked when the prover is created and again at every
/// step and at finalization (expiry and the step quota).
pub struct LicensedProver {
    ivc: CircomIvc,
    license: String,
    quota: Option<u64>,
}

impl LicensedProver {
    /// `license`: the `EnterpriseLicenseKey`; `r1cs`: the compiled step
    /// circuit; `z0`: the initial state as decimal strings.
    pub fn new(license: &str, r1cs: &[u8], z0: &[String]) -> Result<Self, SdkError> {
        let quota = claims(license)?.max_steps;
        Ok(Self {
            ivc: CircomIvc::new(r1cs, parse_state(z0)?)?,
            license: license.to_string(),
            quota,
        })
    }

    /// Folds one more step, given its Circom witness (`.wtns` bytes).
    pub fn prove_step(&mut self, wtns: &[u8]) -> Result<(), SdkError> {
        claims(&self.license)?;
        if let Some(max_steps) = self.quota {
            if self.ivc.acc.i >= max_steps {
                return Err(SdkError::QuotaExceeded { max_steps });
            }
        }
        self.ivc.prove_step(wtns, &mut rand::rngs::OsRng)
    }

    /// Checks the prover's own state.
    pub fn verify(&self) -> Result<(), SdkError> {
        self.ivc.verify()
    }

    /// Number of steps folded so far.
    pub fn steps(&self) -> u64 {
        self.ivc.acc.i
    }

    /// Current state `z_i` as decimal strings.
    pub fn state(&self) -> Vec<String> {
        state_strings(&self.ivc.acc.zi)
    }

    /// Serialized size of the prover state in bytes; constant in `steps`.
    pub fn state_size(&self) -> usize {
        use ark_serialize::CanonicalSerialize;
        self.ivc.acc.compressed_size()
    }

    /// Produces a succinct zero-knowledge proof of the computation so far.
    pub fn finalize(&self) -> Result<Vec<u8>, SdkError> {
        claims(&self.license)?;
        self.ivc.finalize(&mut rand::rngs::OsRng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeno_license::{issue, DEV_PRIVATE_KEY};

    const R1CS: &[u8] = include_bytes!("../fixtures/step.r1cs");
    const WTNS: [&[u8]; 2] = [
        include_bytes!("../fixtures/step0.wtns"),
        include_bytes!("../fixtures/step1.wtns"),
    ];

    fn dev_license(expires_at: u64, max_steps: Option<u64>) -> String {
        issue(
            &DEV_PRIVATE_KEY,
            &Claims {
                customer: "tests".into(),
                plan: "dev".into(),
                expires_at,
                max_steps,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_prover_needs_a_license_and_respects_its_quota() {
        // These tests run in a build without a vendor key.
        assert!(zeno_license::vendor_key_is_development());
        let z0 = vec!["3".to_string()];
        let far = unix_now() + 3600;

        // No license, a license of another vendor, an expired one.
        assert!(matches!(
            LicensedProver::new("", R1CS, &z0),
            Err(SdkError::License(_))
        ));
        let (other, _) = zeno_license::generate_keypair();
        let foreign = issue(
            &other,
            &Claims {
                customer: "x".into(),
                plan: "y".into(),
                expires_at: far,
                max_steps: None,
            },
        )
        .unwrap();
        assert!(matches!(
            LicensedProver::new(&foreign, R1CS, &z0),
            Err(SdkError::License(_))
        ));
        assert!(matches!(
            LicensedProver::new(&dev_license(1, None), R1CS, &z0),
            Err(SdkError::License(_))
        ));

        // A quota of one step: the second step is refused, the proof of the
        // first is still produced.
        let license = dev_license(far, Some(1));
        let info = check_license(&license).unwrap();
        assert_eq!((info.max_steps, info.development_build), (Some(1), true));
        let mut prover = LicensedProver::new(&license, R1CS, &z0).unwrap();
        prover.prove_step(WTNS[0]).unwrap();
        assert!(matches!(
            prover.prove_step(WTNS[1]),
            Err(SdkError::QuotaExceeded { max_steps: 1 })
        ));
        assert_eq!(prover.steps(), 1);
        let proof = prover.finalize().unwrap();
        let params = crate::CircomParams::setup(R1CS).unwrap();
        assert_eq!(statement_of(&params.verify_proof(&proof).unwrap()).steps, 1);
    }
}
