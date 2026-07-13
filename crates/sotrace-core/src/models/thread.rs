//! Thread trace models for Android SO analysis
//!
//! Thread tracking is essential in Android SO reverse engineering because:
//! - A single SO may be called by multiple Java threads (JNI)
//! - SO internal pthread_create/pthread_exit creates worker threads
//! - Mutex/futex/condvar synchronization is key for race condition analysis
//! - Context switches determine which thread runs at which step
//! - Thread stack ranges and TLS addresses are needed for memory analysis

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Thread metadata
// ---------------------------------------------------------------------------

/// Thread metadata — recorded once when a thread is created or first seen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// OS thread ID (gettid on Linux/Android)
    pub thread_id: u32,
    /// pthread_t value (optional, may not be available for all threads)
    pub pthread_id: Option<u64>,
    /// Thread that created this one (parent, 0 = main thread or unknown)
    pub parent_thread_id: u32,
    /// Step number when this thread was created/first seen
    pub create_step: u64,
    /// Step number when this thread exited (None if still alive)
    pub exit_step: Option<u64>,
    /// Thread name (set via prctl(PR_SET_NAME) or pthread_setname_np)
    pub name: Option<String>,
    /// Stack base address (lowest address, grows down on ARM64)
    pub stack_base: u64,
    /// Stack size in bytes
    pub stack_size: u64,
    /// Thread-Local Storage (TLS) address
    pub tls_addr: u64,
    /// Whether this thread was attached via JNI AttachCurrentThread
    pub is_jni_attached: bool,
}

// ---------------------------------------------------------------------------
// Thread state
// ---------------------------------------------------------------------------

/// Thread state — extended with Android-specific states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadState {
    /// Thread is currently executing on a CPU core
    Running,
    /// Thread is runnable but not currently scheduled
    Runnable,
    /// Thread is blocked (generic)
    Blocked,
    /// Thread is waiting for a mutex (pthread_mutex_lock)
    WaitingForLock,
    /// Thread is waiting on a futex (futex(FUTEX_WAIT))
    WaitingForFutex,
    /// Thread is waiting on a condition variable (pthread_cond_wait)
    WaitingForCondvar,
    /// Thread is waiting for I/O (read/write/poll)
    WaitingForIO,
    /// Thread is sleeping (nanosleep / sleep)
    Sleeping,
    /// Thread has terminated
    Terminated,
}

impl ThreadState {
    /// Check if this state represents a waiting/blocked state
    pub fn is_waiting(&self) -> bool {
        matches!(
            self,
            ThreadState::Blocked
                | ThreadState::WaitingForLock
                | ThreadState::WaitingForFutex
                | ThreadState::WaitingForCondvar
                | ThreadState::WaitingForIO
        )
    }

    /// Check if the thread is alive (not terminated)
    pub fn is_alive(&self) -> bool {
        !matches!(self, ThreadState::Terminated)
    }

    /// Stable, human-readable name for this state.
    ///
    /// Used as a serialization-friendly key in analysis output (e.g. per-state
    /// residency tables) so consumers don't depend on the enum's Debug form.
    pub fn name(&self) -> &'static str {
        match self {
            ThreadState::Running => "Running",
            ThreadState::Runnable => "Runnable",
            ThreadState::Blocked => "Blocked",
            ThreadState::WaitingForLock => "WaitingForLock",
            ThreadState::WaitingForFutex => "WaitingForFutex",
            ThreadState::WaitingForCondvar => "WaitingForCondvar",
            ThreadState::WaitingForIO => "WaitingForIO",
            ThreadState::Sleeping => "Sleeping",
            ThreadState::Terminated => "Terminated",
        }
    }
}

/// Thread state change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadStateChange {
    /// Step number when the change occurred
    pub step: u64,
    /// Thread ID
    pub thread_id: u32,
    /// New thread state
    pub new_state: ThreadState,
    /// Previous thread state (for delta)
    pub prev_state: Option<ThreadState>,
    /// Which thread was running before this change (context switch info)
    pub prev_running_thread: Option<u32>,
}

// ---------------------------------------------------------------------------
// Thread synchronization events
// ---------------------------------------------------------------------------

/// Synchronization event type — covers Android/Linux synchronization primitives
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncEventType {
    // Mutex operations
    /// pthread_mutex_lock — attempting to acquire
    MutexLock,
    /// pthread_mutex_lock — successfully acquired
    MutexLocked,
    /// pthread_mutex_unlock — releasing
    MutexUnlock,
    /// pthread_mutex_trylock — non-blocking attempt
    MutexTryLock,

    // Futex operations
    /// futex(FUTEX_WAIT) — kernel-level wait
    FutexWait,
    /// futex(FUTEX_WAKE) — kernel-level wake
    FutexWake,
    /// futex(FUTEX_WAKE) with count of threads woken
    FutexWakeCount,

    // Condition variable operations
    /// pthread_cond_wait — waiting on condvar
    CondvarWait,
    /// pthread_cond_signal — waking one waiter
    CondvarSignal,
    /// pthread_cond_broadcast — waking all waiters
    CondvarBroadcast,

    // RW-lock operations
    /// pthread_rwlock_rdlock — read lock acquire
    RwLockRead,
    /// pthread_rwlock_wrlock — write lock acquire
    RwLockWrite,
    /// pthread_rwlock_unlock — releasing rwlock
    RwLockUnlock,

    // Barrier operations
    /// pthread_barrier_wait — waiting at barrier
    BarrierWait,

    // Semaphore operations
    /// sem_wait — semaphore wait
    SemWait,
    /// sem_post — semaphore post
    SemPost,
}

/// The synchronization *primitive class* an address represents, derived from
/// the `SyncEventType` of operations seen on it.
///
/// Coarser than `SyncEventType`: the various mutex operations
/// (`MutexLock`/`MutexLocked`/`MutexTryLock`/`MutexUnlock`) all collapse to
/// `Mutex`, because they operate on the same pthread_mutex_t object. Used to
/// annotate producer-consumer `sync_mechanism` so the reported mechanism is a
/// typed primitive, not a bare address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncPrimitiveKind {
    /// pthread_mutex_* — exclusive lock
    Mutex,
    /// pthread_rwlock_* — reader/writer lock
    RwLock,
    /// sem_* — counting semaphore
    Semaphore,
    /// futex(FUTEX_WAIT/WAKE) — kernel-level wait/wake word
    Futex,
    /// pthread_cond_* — condition variable
    Condvar,
    /// pthread_barrier_* — rendezvous barrier
    Barrier,
}

impl SyncEventType {
    /// Check if this is a lock acquisition attempt.
    ///
    /// **Holdable** acquires only — operations whose `Success` result makes the
    /// calling thread hold the lock (with a matching release that drops it):
    /// `MutexLock`/`MutexLocked`/`MutexTryLock`, `RwLockRead`/`RwLockWrite`,
    /// `SemWait`, `FutexWait`.
    ///
    /// `CondvarWait` and `BarrierWait` are NOT here: a condvar wait *releases*
    /// its associated mutex before waiting, and a barrier is a rendezvous with
    /// no per-thread hold state. They are synchronization signals instead —
    /// see [`Self::is_sync_signal`]. Counting them as acquires fabricated lock
    /// holds (depth that only ever increases, since neither has a paired
    /// release event), producing false deadlocks.
    pub fn is_acquire(&self) -> bool {
        self.is_holdable_acquire()
    }

    /// A *holdable* acquire: a `Success` result makes the calling thread hold
    /// the lock, and a paired [`Self::is_holdable_release`] drops it. Used by
    /// the analyzer's depth counters (`is_lock_held_at`, critical sections) and
    /// `lock_order` — only these types belong in hold-state bookkeeping.
    pub fn is_holdable_acquire(&self) -> bool {
        matches!(
            self,
            SyncEventType::MutexLock
                | SyncEventType::MutexLocked
                | SyncEventType::MutexTryLock
                | SyncEventType::RwLockRead
                | SyncEventType::RwLockWrite
                | SyncEventType::SemWait
                | SyncEventType::FutexWait
        )
    }

    /// A *holdable* release: drops one unit of the calling thread's hold depth
    /// on the lock. Pairs with [`Self::is_holdable_acquire`]. `FutexWake` is a
    /// single-waiter wake (depth-1 is sound); `FutexWakeCount` is NOT here —
    /// it is emitted by the waker with no per-waiter identity, so it cannot
    /// account per-thread depth correctly (see [`Self::is_sync_signal`]).
    pub fn is_holdable_release(&self) -> bool {
        matches!(
            self,
            SyncEventType::MutexUnlock
                | SyncEventType::RwLockUnlock
                | SyncEventType::SemPost
                | SyncEventType::FutexWake
        )
    }

    /// A synchronization signal that establishes a happens-before edge between
    /// threads but does NOT build per-thread lock-hold state. Used by race
    /// detection (`has_sync_between`) to suppress races between threads that
    /// rendezvous on a condvar/barrier/futex-wake, without polluting the
    /// hold-depth counters (which would fabricate deadlocks).
    ///
    /// - `CondvarWait`/`CondvarSignal`/`CondvarBroadcast`: condvar rendezvous
    ///   (the wait releases its mutex; the signal/broadcast wakes waiters).
    /// - `BarrierWait`: all parties release simultaneously — no single release.
    /// - `FutexWakeCount`: multi-waiter wake, waker-emitted, no per-waiter id.
    pub fn is_sync_signal(&self) -> bool {
        matches!(
            self,
            SyncEventType::CondvarWait
                | SyncEventType::CondvarSignal
                | SyncEventType::CondvarBroadcast
                | SyncEventType::BarrierWait
                | SyncEventType::FutexWakeCount
        )
    }

    /// Check if this is a *shared* (reader) acquisition — one that does not
    /// exclude other shared holders. Only a read-mode rwlock acquire qualifies:
    /// readers are mutually compatible, so a read acquire never blocks another
    /// reader and cannot, on its own, participate in a lock-ordering deadlock.
    pub fn is_shared_acquire(&self) -> bool {
        matches!(self, SyncEventType::RwLockRead)
    }

    /// Check if this is a lock release.
    ///
    /// Broad superset of [`Self::is_holdable_release`]: also covers
    /// `FutexWakeCount`, `CondvarSignal`, `CondvarBroadcast`, which are
    /// synchronization signals rather than per-thread depth decrements. Kept
    /// broad so `has_sync_between` recognizes the full set of release-side sync
    /// points; the depth-counting match arms use `is_holdable_release` instead.
    pub fn is_release(&self) -> bool {
        matches!(
            self,
            SyncEventType::MutexUnlock
                | SyncEventType::FutexWake
                | SyncEventType::FutexWakeCount
                | SyncEventType::CondvarSignal
                | SyncEventType::CondvarBroadcast
                | SyncEventType::RwLockUnlock
                | SyncEventType::SemPost
        )
    }

    /// Classify this sync operation into its primitive kind.
    ///
    /// The kind is determined purely by the operation type — all variants that
    /// operate on the same primitive collapse together (every mutex operation
    /// is `Mutex`, every condvar operation is `Condvar`, etc.). This is the
    /// inverse of the #109 three-way classification: holdable acquires/releases
    /// map to their concrete primitive, sync signals map to condvar/barrier/
    /// futex, and `FutexWakeCount` (a sync signal) maps to `Futex` since it
    /// operates on a futex word.
    pub fn primitive_kind(&self) -> SyncPrimitiveKind {
        match self {
            SyncEventType::MutexLock
            | SyncEventType::MutexLocked
            | SyncEventType::MutexUnlock
            | SyncEventType::MutexTryLock => SyncPrimitiveKind::Mutex,

            SyncEventType::RwLockRead
            | SyncEventType::RwLockWrite
            | SyncEventType::RwLockUnlock => SyncPrimitiveKind::RwLock,

            SyncEventType::SemWait | SyncEventType::SemPost => SyncPrimitiveKind::Semaphore,

            SyncEventType::FutexWait
            | SyncEventType::FutexWake
            | SyncEventType::FutexWakeCount => SyncPrimitiveKind::Futex,

            SyncEventType::CondvarWait
            | SyncEventType::CondvarSignal
            | SyncEventType::CondvarBroadcast => SyncPrimitiveKind::Condvar,

            SyncEventType::BarrierWait => SyncPrimitiveKind::Barrier,
        }
    }
}

/// Result of a synchronization operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncResult {
    /// Operation succeeded
    Success,
    /// Operation timed out
    Timeout,
    /// Operation would block (trylock failed)
    WouldBlock,
    /// Operation failed with error
    Error,
    /// Operation was interrupted by signal
    Interrupted,
}

/// Thread synchronization event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSyncEvent {
    /// Step number when this event occurred
    pub step: u64,
    /// Thread ID that performed the sync operation
    pub thread_id: u32,
    /// Type of synchronization event
    pub sync_type: SyncEventType,
    /// Address of the synchronization object (mutex, futex word, condvar, etc.)
    pub sync_object_addr: u64,
    /// Result of the operation
    pub result: SyncResult,
    /// How long the thread waited (in nanoseconds, if measurable)
    pub wait_duration_ns: Option<u64>,
}

// ---------------------------------------------------------------------------
// Context switch
// ---------------------------------------------------------------------------

/// Reason for a context switch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwitchReason {
    /// Thread voluntarily yielded (sched_yield)
    Yield,
    /// Thread was preempted by scheduler
    Preemption,
    /// Thread blocked on a synchronization object
    Blocking,
    /// Thread was interrupted (signal, etc.)
    Interrupt,
    /// Thread's time slice expired
    TimeSliceExpired,
    /// Thread migrated to a different CPU core
    Migration,
    /// Unknown/other reason
    Other,
}

/// Context switch record — when CPU execution moves from one thread to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSwitch {
    /// Step number when the switch occurred
    pub step: u64,
    /// Thread that was running before the switch
    pub from_thread: u32,
    /// Thread that started running after the switch
    pub to_thread: u32,
    /// Reason for the switch
    pub switch_reason: SwitchReason,
    /// CPU core where the switch occurred (optional)
    pub cpu_core: Option<u32>,
}

// ---------------------------------------------------------------------------
// Thread statistics
// ---------------------------------------------------------------------------

/// Statistics for a single thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadStats {
    /// Thread ID
    pub thread_id: u32,
    /// Total steps executed by this thread
    pub steps_executed: u64,
    /// Total time spent running (in nanoseconds, if timestamps available)
    pub running_time_ns: Option<u64>,
    /// Number of context switches involving this thread
    pub context_switch_count: u64,
    /// Number of synchronization events
    pub sync_event_count: u64,
    /// Number of lock acquisitions
    pub lock_acquire_count: u64,
    /// Number of lock contentions (had to wait)
    pub lock_contention_count: u64,
    /// Average lock wait duration (in nanoseconds)
    pub avg_lock_wait_ns: Option<u64>,
    /// Number of functions called by this thread
    pub function_call_count: u64,
}
