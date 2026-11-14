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
//!
//! A crash while a record is being written can leave a last line without
//! its newline. Such a record was never acknowledged (its event was not
//! delivered), so [`Meter::with_log`] cuts it off with a warning instead of
//! refusing to start; any other damage still stops the service.

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
    /// A mode-A proof or a mode-B decision (`finalizeUniversal`).
    Proof,
    /// A mode-D proof (`finalizeRecursive`), priced on its own.
    RecursiveProof,
}

/// Counters of one customer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub sessions: u64,
    pub fold_steps: u64,
    pub proofs: u64,
    pub recursive_proofs: u64,
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
    /// restoring the counters from it. An unterminated last line (a write
    /// cut short by a crash) is removed first, see [`repair_torn_tail`].
    pub fn with_log(path: &Path) -> io::Result<Self> {
        if let Some(cut) = repair_torn_tail(path)? {
            eprintln!(
                "warning: usage log {}: removed an unterminated last record ({cut} bytes) left by an interrupted write; it was never acknowledged",
                path.display()
            );
        }
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
        Event::RecursiveProof => usage.recursive_proofs += 1,
    }
}

/// Removes an unterminated last line from the log at `path`, returning its
/// length, or `None` if the log ends with a newline (or does not exist).
///
/// [`Meter::record`] acknowledges an event only after the whole line,
/// newline included, was written and synced; a line without its newline is
/// therefore a record that was never acknowledged, and nothing was delivered
/// for it.
pub fn repair_torn_tail(path: &Path) -> io::Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    // Scan back from the end for the last newline, in small blocks.
    let mut end = len;
    let mut block = [0u8; 4096];
    loop {
        let start = end.saturating_sub(block.len() as u64);
        let chunk = &mut block[..(end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(chunk)?;
        if end == len && chunk.last() == Some(&b'\n') {
            return Ok(None);
        }
        if let Some(i) = chunk.iter().rposition(|b| *b == b'\n') {
            let keep = start + i as u64 + 1;
            file.set_len(keep)?;
            file.sync_data()?;
            return Ok(Some(len - keep));
        }
        if start == 0 {
            // A single, unterminated line: the log held no acknowledged record.
            file.set_len(0)?;
            file.sync_data()?;
            return Ok(Some(len));
        }
        end = start;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interrupted_last_write_is_cut_off_and_nothing_else() {
        let path = std::env::temp_dir().join(format!("zeno-torn-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut meter = Meter::with_log(&path).unwrap();
            meter.record("acme", Event::Session, 1).unwrap();
            meter.record("acme", Event::FoldStep, 2).unwrap();
        }
        let complete = std::fs::read(&path).unwrap();
        let head = Meter::with_log(&path).unwrap().head().to_string();

        // A crash in the middle of the third record.
        let mut torn = complete.clone();
        torn.extend_from_slice(br#"{"ts":3,"customer":"acme","eve"#);
        std::fs::write(&path, &torn).unwrap();
        assert!(verify_log(&path).is_err());
        let meter = Meter::with_log(&path).unwrap();
        assert_eq!(meter.head(), head);
        assert_eq!(meter.usage("acme").fold_steps, 1);
        assert_eq!(std::fs::read(&path).unwrap(), complete);
        drop(meter);

        // A complete record whose newline was not written is not
        // acknowledged either.
        let mut meter = Meter::with_log(&path).unwrap();
        meter.record("acme", Event::Proof, 3).unwrap();
        drop(meter);
        let mut no_newline = std::fs::read(&path).unwrap();
        no_newline.pop();
        std::fs::write(&path, &no_newline).unwrap();
        let mut meter = Meter::with_log(&path).unwrap();
        assert_eq!(meter.usage("acme").proofs, 0);
        // New records continue the chain on a line of their own.
        meter.record("acme", Event::Proof, 4).unwrap();
        drop(meter);
        assert_eq!(verify_log(&path).unwrap().0["acme"].proofs, 1);

        // Damage anywhere else still stops the service.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("fold-step", "session", 1)).unwrap();
        assert!(Meter::with_log(&path).is_err());

        // A log that is a single torn line held nothing acknowledged.
        std::fs::write(&path, b"{\"ts\":1").unwrap();
        assert_eq!(
            Meter::with_log(&path).unwrap().usage("acme"),
            Usage::default()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let _ = std::fs::remove_file(&path);
    }
}
