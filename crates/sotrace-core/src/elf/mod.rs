//! ELF parser — parses SO file metadata using the `object` crate
//!
//! The actual parsing implementation lives in `sotrace-engine::elf` (it needs
//! the delta-store hash helpers). This module defines the result container
//! [`ParsedSoFile`] that carries the SOFile plus its segments, symbols, and
//! functions, so callers don't lose the parsed detail.

use crate::models::so_file::SOFile;
use crate::models::so_function::SOFunction;
use crate::models::so_segment::SOSegment;
use crate::models::so_symbol::SOSymbol;
use serde::{Deserialize, Serialize};

/// Result of parsing an ELF/SO file: the file metadata plus all extracted
/// segments, symbols, and functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSoFile {
    /// SO file metadata (id is 0 until persisted)
    pub so_file: SOFile,
    /// Extracted segments / sections
    pub segments: Vec<SOSegment>,
    /// Extracted symbols (dynamic + static)
    pub symbols: Vec<SOSymbol>,
    /// Extracted functions (function symbols with names + sizes)
    pub functions: Vec<SOFunction>,
}

impl ParsedSoFile {
    /// Build a function-address → name lookup map.
    ///
    /// The map covers all functions with a non-empty name. When multiple
    /// functions share an address (rare), the last one wins.
    pub fn function_name_map(&self) -> std::collections::HashMap<u64, String> {
        self.functions
            .iter()
            .filter(|f| !f.name.is_empty())
            .map(|f| (f.offset, f.name.clone()))
            .collect()
    }

    /// Count of exported functions.
    pub fn exported_function_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_exported).count()
    }

    /// Count of JNI functions (Java_ prefix).
    pub fn jni_function_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_jni).count()
    }
}
