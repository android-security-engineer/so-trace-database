//! Trace stores — domain-specific stores built on the generic delta_store
//!
//! Each trace store uses the DeltaStore<T> foundation for incremental storage
//! but adds domain-specific logic:
//!
//! - **InstructionStore**: stores instruction execution records with address delta encoding
//! - **RegisterStore**: stores register value changes with bitmask delta encoding
//! - **MemoryStore**: stores memory page changes with byte-level delta encoding
//! - **CallStore**: stores function call/return events for call-stack reconstruction
//! - **ThreadStore**: stores thread state changes with dictionary encoding
//! - **JNIStore**: stores JNI boundary call records
//!
//! All stores share the same Timeline and coordinate snapshots via it.

pub mod instruction_store;
pub mod register_store;
pub mod memory_store;
pub mod call_store;
pub mod thread_store;
pub mod jni_store;

pub use instruction_store::InstructionStore;
pub use register_store::RegisterStore;
pub use memory_store::MemoryStore;
pub use call_store::CallStore;
pub use thread_store::ThreadStore;
pub use jni_store::JNIStore;
