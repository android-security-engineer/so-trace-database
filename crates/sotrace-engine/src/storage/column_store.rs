//! Column store — columnar storage with compression

/// Column data type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    UInt64,
    UInt32,
    UInt16,
    UInt8,
    Bool,
    Bytes,
    String,
}

/// Compression codec for a column
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionCodec {
    /// No compression
    None,
    /// Delta encoding + Varint (for monotonically increasing values)
    DeltaVarint,
    /// Dictionary encoding + Varint (for low-cardinality values)
    DictionaryVarint,
    /// Bitmap compression (for boolean/sparse columns)
    Bitmap,
    /// Zstd compression
    Zstd,
    /// LZ4 compression
    Lz4,
    /// Delta + Varint + Zstd (for address/timestamp columns)
    DeltaVarintZstd,
}

/// Column metadata
#[derive(Debug, Clone)]
pub struct ColumnMeta {
    /// Column name
    pub name: String,
    /// Column data type
    pub data_type: ColumnType,
    /// Compression codec
    pub compression: CompressionCodec,
    /// Number of values in this column
    pub row_count: u64,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// Uncompressed size in bytes
    pub uncompressed_size: u64,
}
