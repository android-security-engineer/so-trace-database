//! SO file metadata model

use serde::{Deserialize, Serialize};
use std::path::Path;
use object::read::Object;
use sha2::Digest;

/// Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    Arm,
    AArch64,
    X86,
    X86_64,
}

/// SO file metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOFile {
    /// Unique ID (assigned by storage engine)
    pub id: u64,
    /// File path
    pub path: String,
    /// ELF Build ID
    pub build_id: Option<Vec<u8>>,
    /// Architecture
    pub arch: Architecture,
    /// File size in bytes
    pub file_size: u64,
    /// MD5 hash
    pub md5: [u8; 16],
    /// SHA-256 hash
    pub sha256: [u8; 32],
    /// Runtime load base address
    pub loaded_base_address: u64,
    /// Import timestamp (Unix epoch)
    pub created_at: u64,
}

impl SOFile {
    /// Parse SO file metadata from an ELF file
    pub fn from_elf(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("failed to read ELF file {}: {}", path.display(), error))?;
        let object = object::read::File::parse(data.as_slice())
            .map_err(|error| anyhow::anyhow!("failed to parse ELF file {}: {}", path.display(), error))?;

        let arch = match object.architecture() {
            object::Architecture::Arm => Architecture::Arm,
            object::Architecture::Aarch64 => Architecture::AArch64,
            object::Architecture::I386 => Architecture::X86,
            object::Architecture::X86_64 => Architecture::X86_64,
            other => anyhow::bail!("unsupported ELF architecture {:?}", other),
        };

        let sha256: [u8; 32] = sha2::Sha256::digest(&data).into();
        let md5 = compute_md5(&data);
        let build_id = extract_build_id(&object);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| anyhow::anyhow!("system clock is before Unix epoch: {}", error))?
            .as_secs();

        Ok(Self {
            id: 0,
            path: path.to_string_lossy().into_owned(),
            build_id,
            arch,
            file_size: data.len() as u64,
            md5,
            sha256,
            loaded_base_address: 0,
            created_at,
        })
    }
}

/// Read the first GNU build-id note from an ELF section.
fn extract_build_id(object: &object::read::File<'_>) -> Option<Vec<u8>> {
    use object::read::ObjectSection;

    for section in object.sections() {
        if section.name().ok()? != ".note.gnu.build-id" {
            continue;
        }
        let data = section.data().ok()?;
        if data.len() < 12 {
            return None;
        }
        let namesz = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
        let name_end = 12usize.checked_add(namesz)?;
        let desc_start = (name_end + 3) & !3;
        let desc_end = desc_start.checked_add(descsz)?;
        return (desc_end <= data.len()).then(|| data[desc_start..desc_end].to_vec());
    }
    None
}

/// Compute an MD5 digest without adding another runtime dependency.
///
/// MD5 is retained here because it is part of the on-disk SO metadata model
/// and is useful for compatibility with existing tooling. SHA-256 remains
/// the content identity used by the engine's persistence layer.
fn compute_md5(data: &[u8]) -> [u8; 16] {
    const SHIFT: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let padded_len = (data.len() + 9).div_ceil(64) * 64;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_le_bytes());

    let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        let original = state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((state[1] & state[2]) | (!state[1] & state[3]), i),
                16..=31 => ((state[3] & state[1]) | (!state[3] & state[2]), (5 * i + 1) % 16),
                32..=47 => (state[1] ^ state[2] ^ state[3], (3 * i + 5) % 16),
                _ => (state[2] ^ (state[1] | !state[3]), (7 * i) % 16),
            };
            let rotated = state[0]
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(words[g])
                .rotate_left(SHIFT[i]);
            state[0] = state[3];
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[1].wrapping_add(rotated);
        }
        for i in 0..4 {
            state[i] = state[i].wrapping_add(original[i]);
        }
    }

    let mut digest = [0u8; 16];
    for (word, bytes) in state.iter().zip(digest.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn md5_matches_standard_vectors() {
        assert_eq!(hex(&compute_md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&compute_md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn parses_a_real_shared_library_when_available() {
        let candidates = [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
        ];
        let Some(path) = candidates.iter().map(Path::new).find(|path| path.exists()) else {
            return;
        };

        let data = std::fs::read(path).unwrap();
        let parsed = SOFile::from_elf(path).unwrap();
        assert_eq!(parsed.arch, Architecture::X86_64);
        assert_eq!(parsed.file_size, data.len() as u64);
        let expected_sha256: [u8; 32] = sha2::Sha256::digest(&data).into();
        assert_eq!(parsed.sha256, expected_sha256);
        assert_eq!(parsed.md5, compute_md5(&data));
        assert!(parsed.build_id.is_some());
    }

    #[test]
    fn rejects_non_elf_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-an-elf");
        std::fs::write(&path, b"not an ELF").unwrap();
        let error = SOFile::from_elf(&path).unwrap_err().to_string();
        assert!(error.contains("failed to parse ELF file"));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
