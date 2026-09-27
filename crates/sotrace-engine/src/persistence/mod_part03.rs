
/// Legacy streaming bincode adapter (kept so old blobs still deserialize).
#[allow(dead_code)]
include!("trace_replay.rs");

#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;

// Silence unused-import warning for HashMap in configs that don't use it yet;
// it is re-exported for future trace-persistence consumers.
#[allow(unused_imports)]
use std::collections::HashMap as _HashMap;
