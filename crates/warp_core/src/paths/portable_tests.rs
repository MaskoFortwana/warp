use std::path::{Path, PathBuf};

use super::*;

fn fixture_exe() -> PathBuf {
    Path::new("Tools")
        .join("Warp Portable")
        .join("warp-oss.exe")
}

#[test]
fn root_is_data_folder_next_to_exe() {
    assert_eq!(
        root_for_exe(&fixture_exe()),
        Some(Path::new("Tools").join("Warp Portable").join("data"))
    );
}

#[test]
fn layout_puts_every_directory_under_root() {
    let root = Path::new("Tools").join("Warp Portable").join("data");
    let layout = Layout::new(&root);

    assert_eq!(layout.config, root.join("config"));
    assert_eq!(layout.data, root.join("data"));
    assert_eq!(layout.state, root.join("state"));
    assert_eq!(layout.cache, root.join("cache"));
    assert_eq!(layout.home, root.join("home"));
}

#[test]
fn prepare_creates_every_directory_and_leaves_no_probe_file() {
    let folder = tempfile::tempdir().expect("temp dir");
    let root = folder.path().join("data");

    prepare(&root).expect("prepare should succeed in a writable folder");

    let layout = Layout::new(&root);
    for dir in layout.dirs() {
        assert!(dir.is_dir(), "{} should exist", dir.display());
    }
    let mut entries: Vec<String> = std::fs::read_dir(&root)
        .expect("read root")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    entries.sort();
    assert_eq!(entries, ["cache", "config", "data", "home", "state"]);
}

#[cfg(unix)]
#[test]
fn prepare_fails_in_a_read_only_folder() {
    use std::os::unix::fs::PermissionsExt;

    let folder = tempfile::tempdir().expect("temp dir");
    std::fs::set_permissions(folder.path(), std::fs::Permissions::from_mode(0o555))
        .expect("make folder read-only");
    // Root ignores permission bits, so the check would be meaningless there.
    if std::fs::write(folder.path().join("probe"), b"").is_ok() {
        return;
    }

    let root = folder.path().join("data");
    let err = prepare(&root).expect_err("prepare must fail in a read-only folder");

    assert!(matches!(err, PortableInitError::CreateDir { .. }));
    assert!(err.to_string().contains(&root.display().to_string()));
    std::fs::set_permissions(folder.path(), std::fs::Permissions::from_mode(0o755))
        .expect("restore permissions");
}

#[cfg(feature = "portable")]
#[test]
fn every_warp_directory_resolves_under_root() {
    let root = root();
    let dirs = [
        crate::paths::data_dir(),
        crate::paths::themes_dir(),
        crate::paths::config_local_dir(),
        crate::paths::gui_config_local_dir().expect("gui config dir"),
        crate::paths::tui_config_local_dir(),
        crate::paths::state_dir(),
        crate::paths::tui_state_dir(),
        crate::paths::cache_dir(),
        crate::paths::warp_home_config_dir().expect("home config dir"),
        crate::paths::warp_home_skills_dir().expect("skills dir"),
        crate::paths::warp_home_mcp_config_file_path().expect("mcp config"),
        crate::paths::gui_mcp_config_file_path().expect("gui mcp config"),
        crate::paths::tui_mcp_config_file_path(),
    ];
    for dir in dirs {
        assert!(
            dir.starts_with(root),
            "{} is outside {}",
            dir.display(),
            root.display()
        );
    }
}

#[cfg(feature = "portable")]
#[test]
fn root_has_no_verbatim_prefix() {
    assert!(!root().to_string_lossy().starts_with(r"\\?\"));
}
