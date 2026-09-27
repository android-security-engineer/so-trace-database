//! Bitmap index for low-cardinality columns

/// Bitmap index for efficient filtering on low-cardinality columns
pub struct BitmapIndex {
    /// Index name
    pub name: String,
    /// Number of bits (rows)
    pub bit_count: u64,
    /// Bitmap data
    pub data: Vec<u64>,
}

impl BitmapIndex {
    /// Create a new bitmap index
    pub fn new(name: &str, bit_count: u64) -> Self {
        let word_count = (bit_count as usize + 63) / 64;
        Self {
            name: name.to_string(),
            bit_count,
            data: vec![0u64; word_count],
        }
    }

    /// Set a bit at the given position
    pub fn set(&mut self, pos: u64) {
        let word = pos as usize / 64;
        let bit = pos as usize % 64;
        if word < self.data.len() {
            self.data[word] |= 1 << bit;
        }
    }

    /// Check if a bit is set at the given position
    pub fn get(&self, pos: u64) -> bool {
        let word = pos as usize / 64;
        let bit = pos as usize % 64;
        if word < self.data.len() {
            (self.data[word] >> bit) & 1 == 1
        } else {
            false
        }
    }
}
