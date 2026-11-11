use std::path::Path;

use super::instance_suffix;

#[test]
fn same_path_gives_same_suffix() {
    let path = Path::new(r"C:\Tools\Warp");
    assert_eq!(instance_suffix(path), instance_suffix(path));
}

#[test]
fn different_paths_give_different_suffixes() {
    assert_ne!(
        instance_suffix(Path::new(r"C:\Tools\Warp")),
        instance_suffix(Path::new(r"D:\Tools\Warp"))
    );
}

#[test]
fn suffix_is_case_insensitive() {
    assert_eq!(
        instance_suffix(Path::new(r"C:\Tools\Warp")),
        instance_suffix(Path::new(r"c:\tools\warp"))
    );
}

#[test]
fn suffix_is_underscore_and_16_lowercase_hex_chars() {
    let suffix = instance_suffix(Path::new(r"C:\Tools\Warp"));
    assert_eq!(suffix.len(), 17);
    let hex = suffix
        .strip_prefix('_')
        .expect("suffix starts with underscore");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
}
