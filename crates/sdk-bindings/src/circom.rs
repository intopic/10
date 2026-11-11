//! Parsers for Circom's binary `.r1cs` (constraints) and `.wtns` (witness)
//! files, and their mapping onto an IVC step function.
//!
//! The step template must expose the IVC state as public input `step_in[k]`
//! and output `step_out[k]`; any other input is a private per-step witness.
//! Circom orders wires as `1, outputs, public inputs, private inputs, ...`.

use ark_ff::{BigInteger, PrimeField};
use std::fmt;
use zeno_ivc::{IvcError, R1csStep};

/// Errors of the SDK layer.
#[derive(Debug)]
pub enum SdkError {
    /// The file is truncated or structurally invalid.
    Malformed(&'static str),
    /// The file was compiled for a different prime field.
    WrongField,
    /// The circuit does not have the `step_in[k]` / `step_out[k]` interface.
    BadInterface {
        outputs: usize,
        public_inputs: usize,
    },
    WitnessLength {
        expected: usize,
        got: usize,
    },
    /// The witness' `step_in` is not the current IVC state.
    StateMismatch,
    UnsatisfiedWitness {
        constraint: usize,
    },
    MalformedProof,
    InvalidFieldElement,
    Ivc(IvcError),
}

impl From<IvcError> for SdkError {
    fn from(e: IvcError) -> Self {
        Self::Ivc(e)
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed file: {what}"),
            Self::WrongField => write!(f, "file was compiled for a different prime field"),
            Self::BadInterface {
                outputs,
                public_inputs,
            } => write!(
                f,
                "step circuit needs as many public inputs as outputs \
                 (got {public_inputs} inputs, {outputs} outputs)"
            ),
            Self::WitnessLength { expected, got } => {
                write!(f, "witness has {got} wires, circuit has {expected}")
            }
            Self::StateMismatch => write!(f, "witness step_in is not the current IVC state"),
            Self::UnsatisfiedWitness { constraint } => {
                write!(f, "witness violates constraint {constraint}")
            }
            Self::MalformedProof => write!(f, "malformed proof bytes"),
            Self::InvalidFieldElement => write!(f, "invalid field element"),
            Self::Ivc(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SdkError {}

/// A little-endian cursor over a byte slice.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SdkError> {
        if self.bytes.len() < n {
            return Err(SdkError::Malformed("unexpected end of file"));
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<usize, SdkError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    fn u64(&mut self) -> Result<usize, SdkError> {
        let b = self.take(8)?;
        let v = u64::from_le_bytes(b.try_into().expect("8 bytes"));
        usize::try_from(v).map_err(|_| SdkError::Malformed("section too large"))
    }

    /// Reads a canonical field element of `size` bytes.
    fn field<F: PrimeField>(&mut self, size: usize) -> Result<F, SdkError> {
        let bytes = self.take(size)?;
        let value = F::from_le_bytes_mod_order(bytes);
        // Reject non-canonical encodings (values ≥ p).
        let mut canonical = value.into_bigint().to_bytes_le();
        canonical.resize(size, 0);
        if canonical != bytes {
            return Err(SdkError::Malformed("non-canonical field element"));
        }
        Ok(value)
    }
}

/// Splits a `magic | version | nSections | sections…` container.
fn sections<'a>(bytes: &'a [u8], magic: &[u8; 4]) -> Result<Vec<(usize, &'a [u8])>, SdkError> {
    let mut r = Reader { bytes };
    if r.take(4)? != magic {
        return Err(SdkError::Malformed("bad magic bytes"));
    }
    let _version = r.u32()?;
    let count = r.u32()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let kind = r.u32()?;
        let size = r.u64()?;
        out.push((kind, r.take(size)?));
    }
    Ok(out)
}

fn section<'a>(all: &[(usize, &'a [u8])], kind: usize) -> Result<&'a [u8], SdkError> {
    all.iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, data)| *data)
        .ok_or(SdkError::Malformed("missing section"))
}

fn check_prime<F: PrimeField>(r: &mut Reader<'_>) -> Result<usize, SdkError> {
    let size = r.u32()?;
    let prime = r.take(size)?;
    let mut modulus = F::MODULUS.to_bytes_le();
    if size < modulus.len() {
        return Err(SdkError::WrongField);
    }
    modulus.resize(size, 0);
    if prime != modulus {
        return Err(SdkError::WrongField);
    }
    Ok(size)
}

type Rows<F> = Vec<Vec<(F, usize)>>;

/// A parsed Circom `.r1cs` file.
#[derive(Clone, Debug)]
pub struct CircomR1cs<F: PrimeField> {
    pub num_wires: usize,
    pub num_outputs: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub a: Rows<F>,
    pub b: Rows<F>,
    pub c: Rows<F>,
}

impl<F: PrimeField> CircomR1cs<F> {
    /// Parses and validates a `.r1cs` file for the field `F`.
    pub fn parse(bytes: &[u8]) -> Result<Self, SdkError> {
        let all = sections(bytes, b"r1cs")?;

        let mut header = Reader {
            bytes: section(&all, 1)?,
        };
        let field_size = check_prime::<F>(&mut header)?;
        let num_wires = header.u32()?;
        let num_outputs = header.u32()?;
        let num_public_inputs = header.u32()?;
        let num_private_inputs = header.u32()?;
        let _num_labels = header.u64()?;
        let num_constraints = header.u32()?;

        if num_outputs == 0 || num_outputs != num_public_inputs {
            return Err(SdkError::BadInterface {
                outputs: num_outputs,
                public_inputs: num_public_inputs,
            });
        }
        if num_wires < 1 + num_outputs + num_public_inputs + num_private_inputs {
            return Err(SdkError::Malformed("inconsistent wire counts"));
        }

        let mut body = Reader {
            bytes: section(&all, 2)?,
        };
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..num_constraints {
            for rows in [&mut a, &mut b, &mut c] {
                let terms = body.u32()?;
                let mut row = Vec::new();
                for _ in 0..terms {
                    let wire = body.u32()?;
                    if wire >= num_wires {
                        return Err(SdkError::Malformed("wire index out of range"));
                    }
                    row.push((body.field::<F>(field_size)?, wire));
                }
                rows.push(row);
            }
        }
        Ok(Self {
            num_wires,
            num_outputs,
            num_public_inputs,
            num_private_inputs,
            a,
            b,
            c,
        })
    }

    /// The IVC step function for this circuit with the given wire values.
    pub fn step(&self, assignment: Option<Vec<F>>) -> R1csStep<F> {
        let k = self.num_outputs;
        R1csStep {
            num_wires: self.num_wires,
            a: self.a.clone(),
            b: self.b.clone(),
            c: self.c.clone(),
            z_out_wires: (1..=k).collect(),
            z_in_wires: (k + 1..=2 * k).collect(),
            assignment,
        }
    }
}

/// Parses a Circom `.wtns` file into the full wire assignment.
pub fn parse_wtns<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, SdkError> {
    let all = sections(bytes, b"wtns")?;
    let mut header = Reader {
        bytes: section(&all, 1)?,
    };
    let field_size = check_prime::<F>(&mut header)?;
    let count = header.u32()?;
    let mut body = Reader {
        bytes: section(&all, 2)?,
    };
    let wires = (0..count)
        .map(|_| body.field::<F>(field_size))
        .collect::<Result<Vec<F>, _>>()?;
    if wires.first() != Some(&F::one()) {
        return Err(SdkError::Malformed("wire 0 must be the constant 1"));
    }
    Ok(wires)
}
