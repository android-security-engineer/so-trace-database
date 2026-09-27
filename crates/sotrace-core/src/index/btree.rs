//! B+ tree index implementation

/// B+ tree index for range and point queries
pub struct BTreeIndex {
    /// Index name
    pub name: String,
    /// Key size in bytes
    pub key_size: usize,
    /// Order (max children per internal node)
    pub order: usize,
}

impl BTreeIndex {
    /// Create a new B+ tree index
    pub fn new(name: &str, key_size: usize) -> Self {
        Self {
            name: name.to_string(),
            key_size,
            order: 64, // Default order
        }
    }
}
