//! Portable mode: every Warp directory lives in a `data` folder next to the executable.
//!
//! Only used when the `portable` feature is enabled (see the hooks in [`crate::paths`]). There is
//! deliberately no fallback to the user's profile: if the folder cannot be resolved or written,
//! the app must refuse to start rather than silently leave state on the machine.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const DATA_DIR_NAME: &str = "data";
const PROBE_FILE_NAME: &str = ".write-probe";

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// The directories that replace the platform's per-user locations.
pub(crate) struct Layout {
    pub(crate) config: PathBuf,
    pub(crate) data: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) cache: PathBuf,
    /// Replaces the `.warp*` folder in the user's home directory.
    pub(crate) home: PathBuf,
}

impl Layout {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            config: root.join("config"),
            data: root.join("data"),
            state: root.join("state"),
            cache: root.join("cache"),
            home: root.join("home"),
        }
    }

    fn dirs(&self) -> [&Path; 5] {
        [
            &self.config,
            &self.data,
            &self.state,
            &self.cache,
            &self.home,
        ]
    }
}

#[derive(Debug)]
pub enum PortableInitError {
    ExePath(io::Error),
    CreateDir { path: PathBuf, source: io::Error },
    ProbeWrite { path: PathBuf, source: io::Error },
}

impl fmt::Display for PortableInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExePath(source) => {
                write!(
                    f,
                    "cannot determine the location of the executable: {source}"
                )
            }
            Self::CreateDir { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            Self::ProbeWrite { path, source } => {
                write!(f, "cannot write to {}: {source}", path.display())
            }
        }
    }
}

impl PortableInitError {
    /// Text for the dialog shown when the app refuses to start. There is no log yet at that point,
    /// so this is the only thing the user sees.
    pub fn user_message(&self) -> String {
        match self {
            Self::ExePath(source) => format!(
                "Warp Portable cannot start because it cannot determine where it is located.\n\n\
                 Details: {source}"
            ),
            Self::CreateDir { path, source } | Self::ProbeWrite { path, source } => format!(
                "Warp Portable cannot start because it cannot write to its data folder:\n\n\
                 {}\n\n\
                 Move the Warp Portable folder to a location where you can write (for example \
                 your Desktop or a USB stick) and start it again.\n\n\
                 Details: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PortableInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ExePath(source)
            | Self::CreateDir { source, .. }
            | Self::ProbeWrite { source, .. } => Some(source),
        }
    }
}

/// Returns the portable data folder, `<directory of the executable>\data`.
///
/// Panics if the executable's location cannot be determined. [`init`] runs first in `main` and
/// reports that case to the user, so reaching the panic means `init` was skipped.
pub fn root() -> &'static Path {
    ROOT.get_or_init(|| {
        resolve_root().unwrap_or_else(|err| panic!("Warp Portable has no data folder: {err}"))
    })
}

/// Resolves the data folder, creates every directory in it and checks that it is writable.
///
/// Must run before anything else resolves a path or opens a log file.
pub fn init() -> Result<&'static Path, PortableInitError> {
    let root = match ROOT.get() {
        Some(root) => root,
        None => {
            let resolved = resolve_root()?;
            ROOT.get_or_init(|| resolved)
        }
    };
    prepare(root)?;
    Ok(root)
}

pub(crate) fn layout() -> Layout {
    Layout::new(root())
}

fn resolve_root() -> Result<PathBuf, PortableInitError> {
    let exe = std::env::current_exe().map_err(PortableInitError::ExePath)?;
    // `dunce` resolves links like `std::fs::canonicalize` but avoids the `\\?\` prefix, which
    // shells and some libraries do not accept.
    let exe = dunce::canonicalize(&exe).unwrap_or(exe);
    root_for_exe(&exe).ok_or_else(|| {
        PortableInitError::ExePath(io::Error::new(
            io::ErrorKind::NotFound,
            "the executable has no parent directory",
        ))
    })
}

fn root_for_exe(exe: &Path) -> Option<PathBuf> {
    exe.parent().map(|dir| dir.join(DATA_DIR_NAME))
}

fn prepare(root: &Path) -> Result<(), PortableInitError> {
    for dir in Layout::new(root).dirs() {
        fs::create_dir_all(dir).map_err(|source| PortableInitError::CreateDir {
            path: dir.to_owned(),
            source,
        })?;
    }

    // An existing folder can still be read-only (ACLs, read-only media), so prove a write works.
    let probe = root.join(PROBE_FILE_NAME);
    fs::write(&probe, b"")
        .and_then(|()| fs::remove_file(&probe))
        .map_err(|source| PortableInitError::ProbeWrite {
            path: root.to_owned(),
            source,
        })
}

#[cfg(test)]
#[path = "portable_tests.rs"]
mod tests;
