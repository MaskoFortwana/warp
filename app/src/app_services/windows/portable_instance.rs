//! Per-folder identity for the portable build, so that portable copies in
//! different folders (and an installed WarpOss) never share a single-instance
//! mutex or URI pipe.

use std::path::Path;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Returns `_` followed by 16 lowercase hex characters derived from `root`.
///
/// FNV-1a is implemented inline because the std hashers are not guaranteed to
/// be stable across processes or releases, and every instance must agree.
/// The path is lowercased first because Windows paths are case-insensitive.
pub(super) fn instance_suffix(root: &Path) -> String {
    let hash = root
        .to_string_lossy()
        .to_lowercase()
        .bytes()
        .fold(FNV_OFFSET_BASIS, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
        });
    format!("_{hash:016x}")
}

#[cfg(test)]
#[path = "portable_instance_tests.rs"]
mod tests;
