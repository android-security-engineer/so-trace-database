//! SO symbol model

use serde::{Deserialize, Serialize};

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    Other(u8),
}

/// Symbol binding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolBind {
    Local,
    Global,
    Weak,
    Other(u8),
}

/// A symbol within an SO file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOSymbol {
    /// Unique ID (primary key)
    pub id: u64,
    /// Foreign key → SOFile
    pub so_file_id: u64,
    /// Symbol name
    pub name: String,
    /// Symbol value / address
    pub value: u64,
    /// Symbol size
    pub size: u64,
    /// Symbol type
    pub sym_type: SymbolType,
    /// Symbol binding
    pub bind: SymbolBind,
    /// Whether this is an imported symbol
    pub is_imported: bool,
    /// Whether this is an exported symbol
    pub is_exported: bool,
}
