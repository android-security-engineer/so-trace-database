//! ELF parser — parse SO (shared library) files for metadata extraction
//!
//! Uses the `object` crate for zero-copy ELF parsing.
//! Extracts: architecture, segments, symbols, functions.

use anyhow::Result;
use std::path::Path;

use object::read::{Object, ObjectSegment, ObjectSection, ObjectSymbol};

use sotrace_core::elf::ParsedSoFile;
use sotrace_core::models::so_file::{SOFile, Architecture};
use sotrace_core::models::so_segment::{SOSegment, SegmentType};
use sotrace_core::models::so_symbol::{SOSymbol, SymbolType, SymbolBind};
use sotrace_core::models::so_function::SOFunction;

/// Parse an ELF/SO file and extract metadata, segments, symbols, and functions.
///
/// Returns a [`ParsedSoFile`] carrying the full parsed detail so callers can
/// register it with a `TraceEngine` or persist it.
pub fn parse_elf(path: &Path) -> Result<ParsedSoFile> {
    let data = std::fs::read(path)?;
    parse_elf_bytes(&data, &path.to_string_lossy())
}

/// Parse an ELF/SO from in-memory bytes, labeling it with `path_label` (used
/// only for the `SOFile.path` metadata field; no file is read).
///
/// This is the path-free core of [`parse_elf`], exposed so HTTP/MCP callers
/// that receive raw bytes (e.g. an octet-stream upload) can reuse the same
/// parsing logic without writing a temp file.
pub fn parse_elf_bytes(data: &[u8], path_label: &str) -> Result<ParsedSoFile> {
    let obj = object::read::File::parse(data)
        .map_err(|e| anyhow::anyhow!("Failed to parse binary file: {}", e))?;

    let file_size = data.len() as u64;

    // Compute hashes
    let sha256 = crate::delta_store::types::sha256_hash(data);
    let md5 = compute_md5(data);

    // Determine architecture
    let arch = match obj.architecture() {
        object::Architecture::Aarch64 => Architecture::AArch64,
        object::Architecture::X86_64 => Architecture::X86_64,
        object::Architecture::Arm => Architecture::Arm,
        _ => Architecture::AArch64, // Default for Android
    };

    // Extract segments (loadable segments)
    let mut segments = Vec::new();
    for segment in obj.segments() {
        let seg_name = segment.name()
            .ok()
            .flatten()
            .unwrap_or("")
            .to_string();
        let (file_offset, _file_size) = segment.file_range();

        let seg = SOSegment {
            id: segments.len() as u64,
            so_file_id: 0,
            name: seg_name,
            seg_type: SegmentType::Load,
            offset: file_offset,
            vaddr: segment.address(),
            size: segment.size(),
            flags: 0,
        };
        segments.push(seg);
    }

    // Also extract sections for more detail
    for section in obj.sections() {
        let sec_name = section.name().unwrap_or("").to_string();
        let (file_offset, _file_size) = section.file_range().unwrap_or((0, 0));
        let seg_type = if sec_name.contains("text") {
            SegmentType::Load
        } else if sec_name.contains("data") || sec_name.contains("bss") {
            SegmentType::Load
        } else if sec_name.contains("dynamic") {
            SegmentType::Dynamic
        } else if sec_name.contains("note") {
            SegmentType::Note
        } else {
            SegmentType::Other(0)
        };

        let seg = SOSegment {
            id: segments.len() as u64,
            so_file_id: 0,
            name: sec_name,
            seg_type,
            offset: file_offset,
            vaddr: section.address(),
            size: section.size(),
            flags: 0,
        };
        segments.push(seg);
    }

    // Extract symbols and functions
    let mut symbols = Vec::new();
    let mut functions = Vec::new();

    for symbol in obj.symbols() {
        let name_str = symbol.name().unwrap_or("").to_string();
        let value: u64 = symbol.address();
        let size: u64 = symbol.size();

        let sym_type = match symbol.kind() {
            object::SymbolKind::Unknown => SymbolType::NoType,
            object::SymbolKind::Text => SymbolType::Func,
            object::SymbolKind::Data => SymbolType::Object,
            object::SymbolKind::Section => SymbolType::Section,
            object::SymbolKind::File => SymbolType::File,
            object::SymbolKind::Tls => SymbolType::Tls,
            _ => SymbolType::NoType,
        };

        let bind = if symbol.is_local() {
            SymbolBind::Local
        } else if symbol.is_global() {
            SymbolBind::Global
        } else if symbol.is_weak() {
            SymbolBind::Weak
        } else {
            SymbolBind::Other(0)
        };

        let is_exported = symbol.is_global() && value != 0;
        let is_imported = symbol.is_global() && value == 0;

        let sym = SOSymbol {
            id: symbols.len() as u64,
            so_file_id: 0,
            name: name_str.clone(),
            value,
            size,
            sym_type,
            bind,
            is_imported,
            is_exported,
        };
        symbols.push(sym);

        // If this is a function symbol, also add to functions
        if symbol.kind() == object::SymbolKind::Text && !name_str.is_empty() && size > 0 {
            let is_jni = name_str.starts_with("Java_");
            let func = SOFunction {
                id: functions.len() as u64,
                so_file_id: 0,
                symbol_id: Some(symbols.len() as u64 - 1),
                name: name_str,
                offset: value,
                size: size as u32,
                is_jni,
                is_imported,
                is_exported,
                is_thunk: false,
            };
            functions.push(func);
        }
    }

    // Fallback for stripped binaries: if the static symbol table yielded no
    // functions (Android SOs are typically stripped of .symtab, keeping only
    // .dynsym), recover exported functions from the dynamic symbol table.
    if functions.is_empty() {
        // Track seen names so versioned/aliased dynamic symbols (which appear
        // multiple times in .dynsym) don't produce duplicate function entries.
        let mut seen_names = std::collections::HashSet::new();
        if let Ok(exports) = obj.exports() {
            for exp in exports {
                let name = String::from_utf8_lossy(exp.name()).to_string();
                if name.is_empty() || !seen_names.insert(name.clone()) {
                    continue;
                }
                let is_jni = name.starts_with("Java_");
                let value = exp.address();
                let sym = SOSymbol {
                    id: symbols.len() as u64,
                    so_file_id: 0,
                    name: name.clone(),
                    value,
                    size: 0,
                    sym_type: SymbolType::Func,
                    bind: SymbolBind::Global,
                    is_imported: false,
                    is_exported: true,
                };
                symbols.push(sym);
                let func = SOFunction {
                    id: functions.len() as u64,
                    so_file_id: 0,
                    symbol_id: Some(symbols.len() as u64 - 1),
                    name,
                    offset: value,
                    size: 0,
                    is_jni,
                    is_imported: false,
                    is_exported: true,
                    is_thunk: false,
                };
                functions.push(func);
            }
        }
        // Also record imported symbols (undefined references resolved at load
        // time via PLT) so the import table is populated.
        if let Ok(imports) = obj.imports() {
            for imp in imports {
                let name = String::from_utf8_lossy(imp.name()).to_string();
                if name.is_empty() || !seen_names.insert(name.clone()) {
                    continue;
                }
                symbols.push(SOSymbol {
                    id: symbols.len() as u64,
                    so_file_id: 0,
                    name,
                    value: 0,
                    size: 0,
                    sym_type: SymbolType::NoType,
                    bind: SymbolBind::Global,
                    is_imported: true,
                    is_exported: false,
                });
            }
        }
    }

    // Extract ELF Build ID from the .note.gnu.build-id section, if present.
    let build_id = extract_build_id(&obj);

    let so_file = SOFile {
        id: 0,
        path: path_label.to_string(),
        build_id,
        arch,
        file_size,
        md5,
        sha256,
        loaded_base_address: 0,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };

    Ok(ParsedSoFile {
        so_file,
        segments,
        symbols,
        functions,
    })
}

/// Extract the GNU Build ID (from the .note.gnu.build-id section) as raw bytes.
fn extract_build_id(obj: &object::read::File) -> Option<Vec<u8>> {
    for section in obj.sections() {
        let name = section.name().unwrap_or("");
        if name == ".note.gnu.build-id" {
            let data = section.data().ok()?;
            // ELF note layout: namesz(4) | descsz(4) | type(4) | name | desc
            if data.len() < 12 {
                return None;
            }
            let namesz = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let descsz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
            // name is padded to 4 bytes; desc follows, also padded to 4 bytes.
            let name_pad = (4 - namesz % 4) % 4;
            let desc_start = 12 + namesz + name_pad;
            if desc_start + descsz <= data.len() {
                return Some(data[desc_start..desc_start + descsz].to_vec());
            }
            return None;
        }
    }
    None
}

/// Compute MD5 hash (placeholder — uses CRC32 for now)
fn compute_md5(data: &[u8]) -> [u8; 16] {
    let checksum = crc32fast::hash(data);
    let mut result = [0u8; 16];
    result[..4].copy_from_slice(&checksum.to_le_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-stripped SO with a static symbol table: parse_elf should recover
    /// functions from `obj.symbols()` and skip the dynamic-symbol fallback.
    #[test]
    fn test_parse_non_stripped_so() {
        let path = std::path::Path::new("/tmp/sotest/libtest.so");
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let parsed = parse_elf(path).expect("parse non-stripped SO");
        assert!(!parsed.functions.is_empty(), "should recover functions");
        assert!(parsed.jni_function_count() >= 1, "test SO has a JNI fn");
        assert!(parsed.so_file.build_id.is_some(), "BuildID should be extracted");
    }

    /// A stripped SO (no .symtab, only .dynsym): the static-symbol loop yields
    /// zero functions, so the dynamic-exports fallback must kick in.
    #[test]
    fn test_parse_stripped_so_fallback() {
        let path = std::path::Path::new("/lib/x86_64-linux-gnu/libc.so.6");
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let parsed = parse_elf(path).expect("parse stripped SO");
        assert!(!parsed.functions.is_empty(), "fallback should recover dynsyms");
        assert_eq!(parsed.functions.len(), parsed.exported_function_count(),
            "all dynsym-derived functions are exports");
        // No duplicate function names survive the dedup.
        let mut names: Vec<&str> = parsed.functions.iter().map(|f| f.name.as_str()).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "no duplicate function names");
        // BuildID is present on glibc.
        assert!(parsed.so_file.build_id.is_some(), "glibc has a BuildID");
        assert_eq!(parsed.so_file.build_id.as_ref().unwrap().len(), 20, // sha1 = 20 bytes
            "GNU BuildID is a SHA-1 (20 bytes)");
    }

    /// extract_build_id correctly parses the ELF note layout.
    #[test]
    fn test_build_id_note_layout() {
        let path = std::path::Path::new("/lib/x86_64-linux-gnu/libc.so.6");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let obj = object::read::File::parse(&*data).unwrap();
        let bid = extract_build_id(&obj).expect("glibc has build-id");
        assert_eq!(bid.len(), 20);
        // Cross-check against the `file` command's known format: hex of sha1.
        let hex: String = bid.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.len(), 40);
    }
}
