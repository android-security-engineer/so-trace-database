//! Index engine — B+ tree, bitmap, and other index structures

pub mod btree;
pub mod bitmap;

/// Index type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexType {
    /// B+ tree index for range and point queries
    BTree,
    /// Bitmap index for low-cardinality columns
    Bitmap,
    /// Bloom filter for membership testing
    BloomFilter,
}
