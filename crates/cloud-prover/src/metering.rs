//! Usage metering for pay-per-proof billing.
//!
//! Every billable event is counted per customer and, when a log file is
//! configured, appended (and synced to disk) as one JSON line carrying the
//! SHA-256 of the previous line's hash. An event counts only once its record
//! is on disk: [`Meter::record`] fails otherwise, and the service then
//! delivers nothing for it.
//!
//! What the chain proves. Editing, reordering or removing records *inside*
//! the log breaks the chain, which [`verify_log`] detects. The chain has no
//! secret, so it does **not** by itself detect a log whose last records were
//! cut off, or one rewritten from scratch by whoever controls the file:
//! both are detected only against a head hash kept elsewhere. The current
//! head is returned by [`Meter::head`] and by `GET /v1/usage` (`log_head`);
//! whoever audits the billing should record it periodically outside the
//! machine that holds the log.

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
    log: Sink,
}

enum Sink {
    Memory,
    File(File),
    /// Writes fail after this many records (tests of the billing-failure
    /// path).
    FailingAfter(usize),
}

impl Meter {
    /// A meter that only counts in memory.
    pub fn in_memory() -> Self {
        Self {
            usage: HashMap::new(),
            last_hash: GENESIS.to_string(),
            log: Sink::Memory,
        }
    }

    /// A meter whose log cannot be written after `after` records, to test that nothing is
    /// delivered unbilled.
    #[doc(hidden)]
    pub fn failing_for_tests(after: usize) -> Self {
        Self {
            log: Sink::FailingAfter(after),
            ..Self::in_memory()
        }
    }

    /// The hash of the last record (the genesis value for an empty log):
    /// the value to anchor outside this machine.
    pub fn head(&self) -> &str {
        &self.last_hash
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
            log: Sink::File(log),
        })
    }

    /// Counts one event for `customer` at Unix time `ts`. With a log file,
    /// the event counts only if its record reached the disk; on an error
    /// nothing changes and the caller must not deliver what it was billing.
    pub fn record(&mut self, customer: &str, event: Event, ts: u64) -> io::Result<()> {
        let hash = record_hash(&self.last_hash, ts, customer, event);
        match &mut self.log {
            Sink::Memory => {}
            Sink::FailingAfter(0) => return Err(io::Error::other("usage log is not writable")),
            Sink::FailingAfter(left) => *left -= 1,
            Sink::File(log) => {
                let record = Record {
                    ts,
                    customer: customer.to_string(),
                    event,
                    prev: self.last_hash.clone(),
                    hash: hash.clone(),
                };
                let line = serde_json::to_string(&record).expect("record serializes");
                writeln!(log, "{line}")?;
                log.flush()?;
                log.sync_data()?;
            }
        }
        apply(self.usage.entry(customer.to_string()).or_default(), event);
        self.last_hash = hash;
        Ok(())
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
