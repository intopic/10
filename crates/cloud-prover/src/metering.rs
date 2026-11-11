//! Usage metering for pay-per-proof billing.
//!
//! Every billable event is counted per customer and, when a log file is
//! configured, appended as one JSON line carrying the SHA-256 of the previous
//! line's hash. Deleting, reordering or editing past records breaks the
//! chain, which [`verify_log`] detects.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

/// A billable event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Event {
    Session,
    FoldStep,
    Proof,
}

/// Counters of one customer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub sessions: u64,
    pub fold_steps: u64,
    pub proofs: u64,
}

#[derive(Serialize, Deserialize)]
struct Record {
    ts: u64,
    customer: String,
    event: Event,
    prev: String,
    hash: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record_hash(prev: &str, ts: u64, customer: &str, event: Event) -> String {
    let mut h = Sha256::new();
    h.update(b"zeno-llull/usage/v1");
    h.update(prev.as_bytes());
    h.update(ts.to_le_bytes());
    h.update((customer.len() as u64).to_le_bytes());
    h.update(customer.as_bytes());
    h.update([event as u8]);
    hex(&h.finalize())
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// In-memory counters plus the optional append-only log.
pub struct Meter {
    usage: HashMap<String, Usage>,
    last_hash: String,
    log: Option<File>,
}

impl Meter {
    /// A meter that only counts in memory.
    pub fn in_memory() -> Self {
        Self {
            usage: HashMap::new(),
            last_hash: GENESIS.to_string(),
            log: None,
        }
    }

    /// Opens (or creates) a usage log, verifying its hash chain and
    /// restoring the counters from it.
    pub fn with_log(path: &Path) -> io::Result<Self> {
        let (usage, last_hash) = if path.exists() {
            verify_log(path)?
        } else {
            (HashMap::new(), GENESIS.to_string())
        };
        let log = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            usage,
            last_hash,
            log: Some(log),
        })
    }

    /// Counts one event for `customer` at Unix time `ts`.
    pub fn record(&mut self, customer: &str, event: Event, ts: u64) {
        apply(self.usage.entry(customer.to_string()).or_default(), event);
        let hash = record_hash(&self.last_hash, ts, customer, event);
        if let Some(log) = &mut self.log {
            let record = Record {
                ts,
                customer: customer.to_string(),
                event,
                prev: self.last_hash.clone(),
                hash: hash.clone(),
            };
            let line = serde_json::to_string(&record).expect("record serializes");
            // A billing record that cannot be persisted must not be lost
            // silently: surface it on stderr for the operator.
            if let Err(e) = writeln!(log, "{line}").and_then(|_| log.flush()) {
                eprintln!("usage log write failed: {e}");
            }
        }
        self.last_hash = hash;
    }

    pub fn usage(&self, customer: &str) -> Usage {
        self.usage.get(customer).copied().unwrap_or_default()
    }
}

fn apply(usage: &mut Usage, event: Event) {
    match event {
        Event::Session => usage.sessions += 1,
        Event::FoldStep => usage.fold_steps += 1,
        Event::Proof => usage.proofs += 1,
    }
}

/// Verifies the hash chain of a usage log and returns the per-customer
/// totals and the hash of the last record.
pub fn verify_log(path: &Path) -> io::Result<(HashMap<String, Usage>, String)> {
    let invalid = |line: usize, what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("usage log line {line}: {what}"),
        )
    };
    let mut usage: HashMap<String, Usage> = HashMap::new();
    let mut prev = GENESIS.to_string();
    for (i, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: Record =
            serde_json::from_str(&line).map_err(|_| invalid(i + 1, "not a usage record"))?;
        if record.prev != prev {
            return Err(invalid(i + 1, "broken hash chain"));
        }
        if record.hash != record_hash(&prev, record.ts, &record.customer, record.event) {
            return Err(invalid(i + 1, "record was modified"));
        }
        apply(usage.entry(record.customer).or_default(), record.event);
        prev = record.hash;
    }
    Ok((usage, prev))
}
