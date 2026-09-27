//! Thread analyzer — comprehensive thread analysis for Android SO reverse engineering
//!
//! This is the primary analysis module for SO security analysis. It combines
//! data from ThreadStore, MemoryStore, CallStore, and InstructionStore to
//! detect patterns critical for understanding multi-threaded SO behavior.
//!
//! # Key Analysis Capabilities
//!
//! ## 1. Race Condition Detection
//!
//! Detects when two threads access the same memory location without proper
//! synchronization. This is the #1 vulnerability pattern in Android SO:
//!
//! ```text
//! Thread A: write(addr=0x1000, step=100)  ─┐
//!                                            ├─ NO SYNC ─→ RACE CONDITION!
//! Thread B: read(addr=0x1000, step=150)   ─┘
//! ```
//!
//! Algorithm:
//! 1. For each memory write, record (address, step, thread_id)
//! 2. For each memory read, check if another thread wrote to the same
//!    page between the last sync event and this read
//! 3. If no sync event separates the write and read → potential race
//!
//! ## 2. Deadlock Detection
//!
//! Detects lock ordering violations that can lead to deadlocks:
//!
//! ```text
//! Thread A: lock(M1) → lock(M2)    (order: M1 → M2)
//! Thread B: lock(M2) → lock(M1)    (order: M2 → M1) ← VIOLATION!
//! ```
//!
//! Algorithm:
//! 1. Build a lock graph: for each thread, record lock acquisition order
//! 2. Check for cycles in the lock graph
//! 3. Any cycle = potential deadlock
//!
//! ## 3. Lock Contention Analysis
//!
//! Identifies hot locks and measures contention:
//! - Which locks have the most waiters?
//! - What's the average wait time per lock?
//! - Which threads contend most?
//!
//! ## 4. Thread-Function Association
//!
//! Maps which threads called which functions:
//! - Per-thread call frequency
//! - Thread safety classification (thread-safe vs thread-unsafe)
//! - JNI boundary mapping (which Java threads call which native functions)
include!("thread_analyzer_in01.rs");
include!("thread_analyzer_in02.rs");
include!("thread_analyzer_in03.rs");
include!("thread_analyzer_in04.rs");
include!("thread_analyzer_in05.rs");
include!("thread_analyzer_in06.rs");
include!("thread_analyzer_in07.rs");

#[cfg(test)]
mod tests {
include!("thread_analyzer_in08.rs");
include!("thread_analyzer_in09.rs");
include!("thread_analyzer_in10.rs");
include!("thread_analyzer_in11.rs");
include!("thread_analyzer_in12.rs");
include!("thread_analyzer_in13.rs");
include!("thread_analyzer_in14.rs");
}
