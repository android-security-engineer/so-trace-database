//! Thread analysis handlers — race detection, deadlock detection, contention analysis
//!
//! These endpoints expose the ThreadAnalyzer's capabilities via HTTP.
//! Analysis is performed on the TraceEngine associated with each trace_id.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET  | `/api/v1/traces/{id}/threads` | List all threads (metadata + stats) |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}` | Get a single thread's info |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}/timeline` | Get a thread's timeline |
//! | GET  | `/api/v1/traces/{id}/threads/{thread_id}/sync-events` | Get sync events for a thread |
//! | GET  | `/api/v1/traces/{id}/threads/sync-events` | Query sync events (filterable) |
//! | GET  | `/api/v1/traces/{id}/threads/context-switches` | Query context switches |
//! | POST | `/api/v1/traces/{id}/analyze/threads` | Run full thread analysis |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/races` | Detect race conditions only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/deadlocks` | Detect deadlocks only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/contentions` | Analyze lock contentions only |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/function-safety` | Classify function thread safety |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/function-assoc` | Analyze thread-function associations |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/data-flows` | Analyze inter-thread data flows |
//! | GET  | `/api/v1/traces/{id}/analyze/threads/producer-consumer` | Detect producer-consumer patterns |
include!("thread_analysis_in01.rs");
include!("thread_analysis_in02.rs");
#[cfg(test)]
mod tests {
include!("thread_analysis_in03.rs");
include!("thread_analysis_in04.rs");
}
