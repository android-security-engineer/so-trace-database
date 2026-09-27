//! SO function model

use serde::{Deserialize, Serialize};

/// A function within an SO file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOFunction {
    /// Unique ID (primary key)
    pub id: u64,
    /// Foreign key → SOFile
    pub so_file_id: u64,
    /// Foreign key → SOSymbol (optional, if symbol exists)
    pub symbol_id: Option<u64>,
    /// Function name (may be "sub_XXXX" format for unnamed functions)
    pub name: String,
    /// Offset within the SO file
    pub offset: u64,
    /// Function size in bytes
    pub size: u32,
    /// Whether this is a JNI function (Java_ prefix or RegisterNatives)
    pub is_jni: bool,
    /// Whether this is an imported function (PLT stub)
    pub is_imported: bool,
    /// Whether this is an exported function
    pub is_exported: bool,
    /// Whether this is a thunk/stub function
    pub is_thunk: bool,
}
