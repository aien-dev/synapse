//! Group commit for concurrent submitters (leader and followers).
//!
//! Each submitter runs the stateless half of an ingest ([`SynapseStore::prepare_ingest`]:
//! signature check, blob digests, WAL v2 payload encoding with its SHA-256 and CRC-32C)
//! on its own thread with no lock held, then joins a bounded queue. Whoever finds no
//! active leader becomes the leader: it takes up to `max_batch_records` queued
//! submissions, checks them against committed state in queue order (so the outcome is
//! the same as committing them one after another), writes the accepted ones as one WAL v2
//! batch with one `fdatasync`, applies them, and only then fills every waiter's result.
//! A waiter is acknowledged only after the batch holding its record is durable, and the
//! WAL sequence order equals queue order equals acknowledgment order.
//!
//! Readers keep reading committed state while a batch is being written: the store's
//! read lock is not held during the write and sync.

use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Counters for batches committed through a [`SharedStore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupCommitStats {
    /// Batches made durable.
    pub batches: u64,
    /// Records in those batches.
    pub records: u64,
    /// Largest batch seen.
    pub max_batch_records: u64,
    /// Batches whose write or sync failed (every waiter in them got an error).
    pub failed_batches: u64,
}

type Slot = Arc<Mutex<Option<SynapseResult<IngestOutcome>>>>;

struct Pending {
    prepared: PreparedIngest,
    slot: Slot,
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Pending>,
    leader_active: bool,
    shutdown: bool,
}

/// A [`SynapseStore`] shared between threads, with group commit for ingests.
///
/// With `FsyncPolicy::GroupCommit` concurrent [`SharedStore::submit`] calls are batched.
/// With the legacy policies submissions are committed one at a time in queue order,
/// exactly as `SynapseStore::ingest_changeset` would (one record, one sync).
pub struct SharedStore {
    state: RwLock<SynapseStore>,
    /// Held by whoever writes the WAL (batch leaders and exclusive operations).
    commit_gate: Mutex<()>,
    queue: Mutex<Queue>,
    queue_cv: Condvar,
    v2: bool,
    /// Record codec the store wrote with when last seen (frame flags byte). Submitters
    /// encode with it; a commit re-encodes a record if the codec changed meanwhile.
    codec_hint: AtomicU8,
    max_batch: usize,
    max_delay: Duration,
    max_queue: usize,
    limits: StoreLimits,
    stats: Mutex<GroupCommitStats>,
    /// Set when a leader panicked mid-batch: every later write is refused.
    broken: AtomicBool,
    /// WAL sequence of every acknowledgment, in the order the results were released.
    #[cfg(test)]
    ack_log: Mutex<Vec<WalSeq>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn refusal(code: RefusalCode, msg: impl Into<String>) -> SynapseError {
    SynapseError::new(code, msg)
}

/// Fills a batch's unfilled slots and releases leadership if the leader unwinds.
struct LeaderGuard<'a> {
    shared: &'a SharedStore,
    slots: Vec<Slot>,
    armed: bool,
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.shared.broken.store(true, Ordering::SeqCst);
        for s in &self.slots {
            let mut g = lock(s);
            if g.is_none() {
                *g = Some(Err(refusal(
                    RefusalCode::IoFailure,
                    "group commit leader failed mid-batch; the outcome is unknown (the batch may be durable): reopen, then retry with the same idempotency key",
                )));
            }
        }
        let mut q = lock(&self.shared.queue);
        q.leader_active = false;
        self.shared.queue_cv.notify_all();
    }
}

impl SharedStore {
    /// Share an opened store.
    pub fn new(store: SynapseStore) -> Self {
        let (max_batch, max_delay) = match store.fsync_policy() {
            FsyncPolicy::GroupCommit {
                max_batch_records,
                max_batch_delay_us,
            } => (
                max_batch_records.max(1) as usize,
                Duration::from_micros(u64::from(max_batch_delay_us)),
            ),
            _ => (1, Duration::ZERO),
        };
        Self {
            v2: store.is_wal_v2(),
            codec_hint: AtomicU8::new(store.record_codec().frame_flags()),
            max_batch,
            max_delay,
            max_queue: store.limits().max_inflight_admissions.max(1),
            limits: store.limits().clone(),
            state: RwLock::new(store),
            commit_gate: Mutex::new(()),
            queue: Mutex::new(Queue::default()),
            queue_cv: Condvar::new(),
            stats: Mutex::new(GroupCommitStats::default()),
            broken: AtomicBool::new(false),
            #[cfg(test)]
            ack_log: Mutex::new(Vec::new()),
        }
    }

    /// Open a store and share it.
    pub fn open(
        root_dir: impl AsRef<Path>,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
    ) -> SynapseResult<Self> {
        SynapseStore::open(root_dir, fsync_policy, recovery_policy, limits).map(Self::new)
    }

    /// Open a store on a raw block device ([`SynapseStore::open_block_device`]).
    pub fn open_block_device(
        cfg: &crate::BlockDeviceConfig,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
    ) -> SynapseResult<Self> {
        SynapseStore::open_block_device(cfg, fsync_policy, recovery_policy, limits).map(Self::new)
    }

    /// Read committed state. Not blocked by a batch write in progress.
    pub fn read(&self) -> RwLockReadGuard<'_, SynapseStore> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, SynapseStore> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` with exclusive access, after any batch in progress has finished.
    pub fn with_exclusive<R>(&self, f: impl FnOnce(&mut SynapseStore) -> R) -> R {
        let _gate = lock(&self.commit_gate);
        let mut st = self.write_state();
        let r = f(&mut st);
        self.codec_hint
            .store(st.record_codec().frame_flags(), Ordering::Relaxed);
        r
    }

    /// Exclusive access without locking (the borrow checker proves no one else has it).
    pub fn get_mut(&mut self) -> &mut SynapseStore {
        self.state.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    /// Unwrap the store.
    pub fn into_inner(self) -> SynapseStore {
        self.state.into_inner().unwrap_or_else(|e| e.into_inner())
    }

    /// Group commit counters so far.
    pub fn stats(&self) -> GroupCommitStats {
        *lock(&self.stats)
    }

    /// WAL sequence of every group-commit acknowledgment, in release order (tests only).
    #[cfg(test)]
    pub(crate) fn ack_log(&self) -> Vec<WalSeq> {
        lock(&self.ack_log).clone()
    }

    /// Refuse new submissions, let every queued one finish (commit or refusal), then
    /// return. Submissions after this call get `BackpressureOverCapacity`.
    pub fn shutdown(&self) {
        let mut q = lock(&self.queue);
        q.shutdown = true;
        self.queue_cv.notify_all();
        while q.leader_active || !q.items.is_empty() {
            if !q.leader_active {
                // Queued work with no leader (its submitters will lead it; wake them).
                self.queue_cv.notify_all();
            }
            q = self
                .queue_cv
                .wait_timeout(q, Duration::from_millis(10))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn admission_refusal(&self, q: &Queue) -> Option<SynapseError> {
        if self.broken.load(Ordering::SeqCst) {
            return Some(refusal(
                RefusalCode::IoFailure,
                "group commit leader failed mid-batch; the store refuses writes until reopened",
            ));
        }
        if q.shutdown {
            return Some(refusal(
                RefusalCode::BackpressureOverCapacity,
                "store is shutting down and admits no new submissions",
            ));
        }
        if q.items.len() >= self.max_queue {
            return Some(refusal(
                RefusalCode::BackpressureOverCapacity,
                format!(
                    "admission queue at capacity ({}/{})",
                    q.items.len(),
                    self.max_queue
                ),
            ));
        }
        None
    }

    /// Submit a changeset. Returns after the record is durable (or refused). Safe to call
    /// from many threads at once; concurrent calls share one WAL sync per batch.
    ///
    /// A refusal is not proof that nothing was committed. When the batch rollback fails
    /// (the store is then poisoned) or the leader dies after its write, the caller gets
    /// `IoFailure` although the batch may already be durable. Clients must reopen and
    /// retry with the same idempotency key; the retry returns `IdempotentDuplicate` if the
    /// first attempt did land, and commits exactly once otherwise.
    pub fn submit(
        &self,
        envelope: ChangesetEnvelope,
        blobs: &[(BlobDigest, Vec<u8>)],
    ) -> SynapseResult<IngestOutcome> {
        // 1. Backpressure (queue bound, shutdown, and the store's simulated in-flight count).
        if let Some(e) = self.admission_refusal(&lock(&self.queue)) {
            return Err(e);
        }
        {
            let st = self.read();
            if st.inflight_admissions >= st.limits.max_inflight_admissions {
                return Err(refusal(
                    RefusalCode::BackpressureOverCapacity,
                    format!(
                        "admission queue at capacity ({}/{})",
                        st.inflight_admissions, st.limits.max_inflight_admissions
                    ),
                ));
            }
        }
        // 2. Stateless half, in parallel on the caller's thread.
        let codec = RecordCodec::from_frame_flags(self.codec_hint.load(Ordering::Relaxed))
            .unwrap_or(RecordCodec::BinaryV2);
        let prepared =
            SynapseStore::prepare_ingest(&self.limits, envelope, blobs, self.v2.then_some(codec))?;

        let slot: Slot = Arc::new(Mutex::new(None));
        let mut q = lock(&self.queue);
        if let Some(e) = self.admission_refusal(&q) {
            return Err(e);
        }
        q.items.push_back(Pending {
            prepared,
            slot: Arc::clone(&slot),
        });
        if !self.max_delay.is_zero() {
            // A lingering leader waits for the batch to fill.
            self.queue_cv.notify_all();
        }
        loop {
            if let Some(result) = lock(&slot).take() {
                return result;
            }
            if !q.leader_active {
                q.leader_active = true;
                q = self.lead(q, &slot);
                continue;
            }
            q = self.queue_cv.wait(q).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Commit batches until `my_slot` is filled or the queue is empty. Called and returns
    /// with the queue lock held; leadership is released on return.
    fn lead<'a>(&'a self, mut q: MutexGuard<'a, Queue>, my_slot: &Slot) -> MutexGuard<'a, Queue> {
        loop {
            if !self.max_delay.is_zero() && q.items.len() < self.max_batch && !q.shutdown {
                let deadline = Instant::now() + self.max_delay;
                while q.items.len() < self.max_batch && !q.shutdown {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    q = self
                        .queue_cv
                        .wait_timeout(q, deadline - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
            let n = q.items.len().min(self.max_batch);
            let batch: Vec<Pending> = q.items.drain(..n).collect();
            drop(q);
            if !batch.is_empty() {
                let mut guard = LeaderGuard {
                    shared: self,
                    slots: batch.iter().map(|p| Arc::clone(&p.slot)).collect(),
                    armed: true,
                };
                self.commit_batch(batch);
                guard.armed = false;
            }
            q = lock(&self.queue);
            if lock(my_slot).is_some() || q.items.is_empty() {
                q.leader_active = false;
                self.queue_cv.notify_all();
                return q;
            }
            // Followers whose results are ready can return while this leader goes on.
            self.queue_cv.notify_all();
        }
    }

    fn commit_batch(&self, mut batch: Vec<Pending>) {
        let _gate = lock(&self.commit_gate);
        if !self.v2 {
            // Legacy policies: one record and one sync at a time, in queue order.
            let mut st = self.write_state();
            for p in batch {
                let r = st.ingest_prepared(p.prepared);
                *lock(&p.slot) = Some(r);
            }
            return;
        }

        let mut st = self.write_state();
        if let Err(e) = st.check_writable() {
            drop(st);
            for p in &batch {
                *lock(&p.slot) = Some(Err(e.clone()));
            }
            return;
        }

        // Stateful checks in queue order against committed state plus the records
        // accepted earlier in this batch (same outcome as committing one by one).
        let mut overlay = BatchOverlay::default();
        let mut planned = Vec::with_capacity(batch.len());
        let mut accepted = Vec::new();
        let mut seq = st.committed_seq;
        self.codec_hint
            .store(st.record_codec().frame_flags(), Ordering::Relaxed);
        for (i, p) in batch.iter_mut().enumerate() {
            let mut pl = st.plan_ingest(&p.prepared, &overlay);
            if matches!(pl, Planned::Accept) {
                if let Err(error) = st.conform_v2(&mut p.prepared) {
                    pl = Planned::Refused {
                        error,
                        depends_on_batch: false,
                    };
                } else {
                    seq = seq.next();
                    let env = &p.prepared.envelope;
                    overlay.idempotency.insert(
                        (env.repo_id.clone(), env.idempotency_key),
                        (seq, p.prepared.changeset_id),
                    );
                    overlay
                        .changesets
                        .insert(p.prepared.changeset_id, env.repo_id.clone());
                    for m in &env.mutations {
                        if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                            overlay.blobs.insert(*blob_digest);
                        }
                    }
                    accepted.push(i);
                }
            }
            planned.push(pl);
        }

        // Outcomes that do not depend on this batch are final now.
        for (p, pl) in batch.iter().zip(&planned) {
            let r = match pl {
                Planned::Duplicate {
                    wal_seq,
                    changeset_id,
                    depends_on_batch: false,
                } => Ok(IngestOutcome::IdempotentDuplicate {
                    wal_seq: *wal_seq,
                    changeset_id: *changeset_id,
                }),
                Planned::Refused {
                    error,
                    depends_on_batch: false,
                } => Err(error.clone()),
                _ => continue,
            };
            *lock(&p.slot) = Some(r);
        }
        if accepted.is_empty() {
            return;
        }

        let mut ticket = match st.v2_begin() {
            Ok(t) => t,
            Err(e) => {
                drop(st);
                self.fail_dependent(&batch, &planned, &e);
                return;
            }
        };
        drop(st);

        // One write and one fdatasync for the whole batch, with no store lock held.
        let result = {
            let encoded: Vec<&wal2::EncodedRecord> = accepted
                .iter()
                .map(|&i| batch[i].prepared.encoded.as_ref().expect("checked above"))
                .collect();
            SynapseStore::v2_write(&mut ticket, &encoded)
        };

        let mut st = self.write_state();
        match st.v2_finish(ticket, result) {
            Ok(placed) => {
                let mut outcomes = Vec::with_capacity(accepted.len());
                for (k, &i) in accepted.iter().enumerate() {
                    let p = &batch[i].prepared;
                    let enc = p.encoded.as_ref().expect("checked above");
                    st.apply_v2_ingest(&placed[k], p.record(), &enc.inline);
                    outcomes.push(IngestOutcome::Committed {
                        wal_seq: placed[k].seq,
                        changeset_id: p.changeset_id,
                        frame_sha256: placed[k].frame_sha256,
                        durability: DurabilityGuarantee::FsyncBeforeAck,
                    });
                }
                drop(st);
                {
                    let mut s = lock(&self.stats);
                    s.batches += 1;
                    s.records += accepted.len() as u64;
                    s.max_batch_records = s.max_batch_records.max(accepted.len() as u64);
                }
                for (&i, outcome) in accepted.iter().zip(outcomes) {
                    #[cfg(test)]
                    if let IngestOutcome::Committed { wal_seq, .. } = &outcome {
                        lock(&self.ack_log).push(*wal_seq);
                    }
                    *lock(&batch[i].slot) = Some(Ok(outcome));
                }
                for (p, pl) in batch.iter().zip(&planned) {
                    let r = match pl {
                        Planned::Duplicate {
                            wal_seq,
                            changeset_id,
                            depends_on_batch: true,
                        } => Ok(IngestOutcome::IdempotentDuplicate {
                            wal_seq: *wal_seq,
                            changeset_id: *changeset_id,
                        }),
                        Planned::Refused {
                            error,
                            depends_on_batch: true,
                        } => Err(error.clone()),
                        _ => continue,
                    };
                    *lock(&p.slot) = Some(r);
                }
            }
            Err(e) => {
                drop(st);
                lock(&self.stats).failed_batches += 1;
                self.fail_dependent(&batch, &planned, &e);
            }
        }
    }

    /// The batch write failed: every accepted record gets `e`, and every outcome that
    /// relied on a record of this batch gets a retryable `IoFailure` (its basis is gone).
    fn fail_dependent(&self, batch: &[Pending], planned: &[Planned], e: &SynapseError) {
        for (p, pl) in batch.iter().zip(planned) {
            let r = match pl {
                Planned::Accept => e.clone(),
                Planned::Duplicate {
                    depends_on_batch: true,
                    ..
                }
                | Planned::Refused {
                    depends_on_batch: true,
                    ..
                } => refusal(
                    RefusalCode::IoFailure,
                    format!(
                        "an earlier record in the same batch was not committed ({}); retry",
                        e.message
                    ),
                ),
                _ => continue,
            };
            *lock(&p.slot) = Some(Err(r));
        }
    }
}
