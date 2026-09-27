// High-throughput ingest with sync and async write modes.
//
// [`TraceEngine::feed_event`] stays immediately queryable (sync) so existing
// CLI/HTTP/MCP tests keep passing. This module is the append-only batch
// ingest used when a capture produces events faster than encoding/fsync.
//
// Default mode is [`WriteMode::Async`]: `ingest` accepts the batch into a
// queue and returns without encoding or applying it. [`TraceIngestor::status`]
// exposes accepted / queryable / durable watermarks; [`TraceIngestor::drain`]
// blocks until the accepted prefix is queryable (and durable when persist
// was configured). Sync and async share [`apply_batch`], which moves events
// into [`TraceEngine::apply_events`] (instruction runs via `write_batch`).
// Drop joins the worker after a Shutdown so already-accepted batches are
// applied rather than discarded.

use anyhow::{anyhow, Result};
use sotrace_core::adapters::TraceEvent;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::engine::TraceEngine;
use crate::persistence::{TraceRepository, TraceStreamMetadata};

/// How a batch is committed on [`TraceIngestor::ingest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Apply (and persist, if configured) on the calling thread. After
    /// `ingest` returns, the batch is queryable.
    Sync,
    /// Enqueue the batch and return. Encoding/apply/fsync run on a worker.
    Async,
}

impl Default for WriteMode {
    fn default() -> Self {
        WriteMode::Async
    }
}

/// Monotonic watermarks for an ingest session.
///
/// Counts are event counts (not step numbers). Invariant:
/// `durable <= queryable <= accepted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestStatus {
    /// Events accepted into the ingest path (queued or applied).
    pub accepted: u64,
    /// Events already applied to the engine and visible to queries.
    pub queryable: u64,
    /// Events appended to the persist blob (0 when persist is off).
    pub durable: u64,
    /// Batches waiting in the async queue (0 in sync mode after ingest).
    pub queued_batches: u64,
    /// Worker currently applying a batch.
    pub in_flight: bool,
}

enum WorkerMsg {
    Batch(Vec<TraceEvent>),
    Shutdown,
}

struct Shared {
    engine: Arc<Mutex<TraceEngine>>,
    persist: Mutex<Option<Arc<Mutex<TraceRepository>>>>,
    persist_id: Mutex<Option<u64>>,
    persist_meta: Mutex<Option<TraceStreamMetadata>>,
    accepted: AtomicU64,
    queryable: AtomicU64,
    durable: AtomicU64,
    queued_batches: AtomicU64,
    in_flight: AtomicBool,
    error: Mutex<Option<String>>,
    fail_next_apply: AtomicBool,
    fail_next_persist: AtomicBool,
    apply_hold: Mutex<Option<mpsc::Receiver<()>>>,
}

/// Append-only ingest front for a [`TraceEngine`].
pub struct TraceIngestor {
    shared: Arc<Shared>,
    mode: WriteMode,
    tx: Mutex<Option<Sender<WorkerMsg>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl TraceIngestor {
    /// Wrap an engine. Default mode is async.
    pub fn new(engine: Arc<Mutex<TraceEngine>>) -> Self {
        Self::with_mode(engine, WriteMode::default())
    }

    /// Wrap an engine with an explicit write mode.
    pub fn with_mode(engine: Arc<Mutex<TraceEngine>>, mode: WriteMode) -> Self {
        let shared = Arc::new(Shared {
            engine,
            persist: Mutex::new(None),
            persist_id: Mutex::new(None),
            persist_meta: Mutex::new(None),
            accepted: AtomicU64::new(0),
            queryable: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            queued_batches: AtomicU64::new(0),
            in_flight: AtomicBool::new(false),
            error: Mutex::new(None),
            fail_next_apply: AtomicBool::new(false),
            fail_next_persist: AtomicBool::new(false),
            apply_hold: Mutex::new(None),
        });
        let ingestor = Self {
            shared,
            mode,
            tx: Mutex::new(None),
            worker: Mutex::new(None),
        };
        if mode == WriteMode::Async {
            ingestor.spawn_worker();
        }
        ingestor
    }

    /// Persist each applied batch as an append-only SOTC chunk.
    ///
    /// Call before the first `ingest`. The blob is created on the first
    /// durable write (`trace_id == 0` assigns an id). Subsequent batches
    /// append; earlier chunks are not rewritten.
    pub fn enable_persist(&self, repo: TraceRepository, meta: TraceStreamMetadata) {
        *self.shared.persist.lock().unwrap() = Some(Arc::new(Mutex::new(repo)));
        *self.shared.persist_meta.lock().unwrap() = Some(meta);
    }

    fn spawn_worker(&self) {
        let (tx, rx) = mpsc::channel();
        *self.tx.lock().unwrap() = Some(tx);
        let shared = Arc::clone(&self.shared);
        let handle = thread::spawn(move || worker_loop(rx, shared));
        *self.worker.lock().unwrap() = Some(handle);
    }

    /// Accept a batch. In sync mode the batch is queryable when this returns.
    /// In async mode it is only accepted; call [`Self::drain`] to wait.
    pub fn ingest(&self, events: Vec<TraceEvent>) -> Result<u64> {
        self.check_error()?;
        let n = events.len() as u64;
        if n == 0 {
            return Ok(self.shared.accepted.load(Ordering::Acquire));
        }
        let accepted = self.shared.accepted.fetch_add(n, Ordering::AcqRel) + n;
        match self.mode {
            WriteMode::Sync => {
                apply_batch(&self.shared, events)?;
            }
            WriteMode::Async => {
                self.shared.queued_batches.fetch_add(1, Ordering::AcqRel);
                let tx = self.tx.lock().unwrap();
                let tx = tx.as_ref().ok_or_else(|| anyhow!("async ingest worker missing"))?;
                tx.send(WorkerMsg::Batch(events))
                    .map_err(|_| anyhow!("async ingest worker exited"))?;
            }
        }
        Ok(accepted)
    }

    /// Current watermarks.
    pub fn status(&self) -> IngestStatus {
        IngestStatus {
            accepted: self.shared.accepted.load(Ordering::Acquire),
            queryable: self.shared.queryable.load(Ordering::Acquire),
            durable: self.shared.durable.load(Ordering::Acquire),
            queued_batches: self.shared.queued_batches.load(Ordering::Acquire),
            in_flight: self.shared.in_flight.load(Ordering::Acquire),
        }
    }

    /// Block until `queryable == accepted` (and `durable == accepted` when
    /// persist is enabled). Events accepted by async ingest are not dropped.
    pub fn drain(&self) -> Result<IngestStatus> {
        if self.mode == WriteMode::Sync {
            self.check_error()?;
            return Ok(self.status());
        }
        let target = self.shared.accepted.load(Ordering::Acquire);
        let need_durable = self.shared.persist.lock().unwrap().is_some();
        loop {
            self.check_error()?;
            let st = self.status();
            let applied = st.queryable >= target;
            let persisted = !need_durable || st.durable >= target;
            if applied && persisted {
                return Ok(st);
            }
            thread::sleep(Duration::from_micros(200));
        }
    }

    /// Persist id assigned on the first durable write, if any.
    pub fn persist_id(&self) -> Option<u64> {
        *self.shared.persist_id.lock().unwrap()
    }

    /// Next apply returns an error before touching the engine (tests / fault injection).
    pub fn fail_next_apply(&self) {
        self.shared.fail_next_apply.store(true, Ordering::Release);
    }

    /// Next persist returns an error after apply; durable is not advanced.
    pub fn fail_next_persist(&self) {
        self.shared.fail_next_persist.store(true, Ordering::Release);
    }

    /// Stall the next apply until the returned sender fires. Sets `in_flight`
    /// before blocking so observers can query the prefix.
    pub fn stall_next_apply(&self) -> Sender<()> {
        let (tx, rx) = mpsc::channel();
        *self.shared.apply_hold.lock().unwrap() = Some(rx);
        tx
    }

    fn check_error(&self) -> Result<()> {
        if let Some(err) = self.shared.error.lock().unwrap().as_ref() {
            return Err(anyhow!("{err}"));
        }
        Ok(())
    }
}

impl Drop for TraceIngestor {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.lock().unwrap().take() {
            let _ = tx.send(WorkerMsg::Shutdown);
        }
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

fn worker_loop(rx: Receiver<WorkerMsg>, shared: Arc<Shared>) {
    while let Ok(msg) = rx.recv() {
        match msg {
            WorkerMsg::Shutdown => break,
            WorkerMsg::Batch(events) => {
                shared.queued_batches.fetch_sub(1, Ordering::AcqRel);
                shared.in_flight.store(true, Ordering::Release);
                let result = apply_batch(&shared, events);
                shared.in_flight.store(false, Ordering::Release);
                if let Err(e) = result {
                    *shared.error.lock().unwrap() = Some(e.to_string());
                    break;
                }
            }
        }
    }
}

fn apply_batch(shared: &Shared, events: Vec<TraceEvent>) -> Result<()> {
    if let Some(rx) = shared.apply_hold.lock().unwrap().take() {
        // Worker already set `in_flight`. Wait so tests can observe the
        // queryable prefix before this batch becomes visible.
        let _ = rx.recv();
    }
    if shared.fail_next_apply.swap(false, Ordering::AcqRel) {
        return Err(anyhow!("injected apply failure"));
    }
    let n = events.len() as u64;
    let persist = shared.persist.lock().unwrap().clone();
    if persist.is_none() {
        let mut eng = shared.engine.lock().unwrap();
        eng.apply_events(events)?;
        // Bump queryable while the engine is still locked so a concurrent
        // query either sees the old prefix or the full new watermark — never
        // a half-applied batch with a stale queryable count.
        shared.queryable.fetch_add(n, Ordering::AcqRel);
        return Ok(());
    }

    // Encode the durable chunk on a second thread while this thread applies.
    // Both sides only borrow `events`. Queryable still advances before the
    // chunk is appended, and a persist failure still leaves durable behind.
    thread::scope(|scope| -> Result<()> {
        let encoded = scope.spawn(|| crate::persistence::trace_codec::compress_chunk(&events));
        {
            let mut eng = shared.engine.lock().unwrap();
            eng.apply_events_ref(&events)?;
            shared.queryable.fetch_add(n, Ordering::AcqRel);
        }
        let repo = persist.expect("persist repo checked above");
        if shared.fail_next_persist.swap(false, Ordering::AcqRel) {
            return Err(anyhow!("injected persist failure"));
        }
        let payload = encoded
            .join()
            .map_err(|_| anyhow!("persist encode thread panicked"))??;
        let mut repo = repo.lock().unwrap();
        let mut id_guard = shared.persist_id.lock().unwrap();
        if id_guard.is_none() {
            let meta = shared
                .persist_meta
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow!("persist metadata missing"))?;
            let id = repo.create_sotc(meta)?;
            *id_guard = Some(id);
        }
        let id = id_guard.unwrap();
        drop(id_guard);
        repo.append_compressed_chunk(id, n as usize, &payload)?;
        shared.durable.fetch_add(n, Ordering::AcqRel);
        Ok(())
    })
}
