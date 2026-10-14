//! Store identity marker and coordination-root resolution (issue #15).
//!
//! crumb.c and Synapse agree on one coordination store only by configuration. A wrong root
//! used to fail silently: each tool granted a claim on the same file in its own store (split
//! brain). The marker `<root>/STORE_ID` gives every store a random identity, so a Synapse
//! agent can be opened *expecting* the identity registered for its repository and is refused
//! when the configured root has a different marker or none.
//!
//! crumb.c (aien-architecture 29780e5) never names `STORE_ID`: it only touches `.lock`,
//! `dirs/`, `agents/`, `continuations/` and `ledger/` under the root, and its `collect_json`
//! walks only `dirs/`, `agents/` and `continuations/`. So the marker is invisible to it and
//! survives its mutations and pruning (checked against the real binary by
//! `scripts/crumb-coord-interop.sh`, I11).

use crate::CoordError;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// File name of the marker, directly under the store root.
pub const STORE_ID_FILE: &str = "STORE_ID";
/// Format tag, first token of the marker. A different tag is refused, never guessed.
pub const STORE_ID_FORMAT: &str = "crumb-coord-store-id/1";

/// Random 128-bit identity of one coordination store.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoreId([u8; 16]);

impl StoreId {
    /// 16 bytes from the OS random source (`/dev/urandom`).
    pub fn random() -> std::io::Result<StoreId> {
        use std::io::Read;
        let mut b = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
        Ok(StoreId(b))
    }

    /// Lowercase hex, 32 characters.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Exactly 32 lowercase hex characters (the form [`StoreId::to_hex`] prints).
    pub fn parse_hex(s: &str) -> Option<StoreId> {
        let s = s.as_bytes();
        if s.len() != 32 {
            return None;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut b = [0u8; 16];
        for (i, out) in b.iter_mut().enumerate() {
            *out = nib(s[2 * i])? << 4 | nib(s[2 * i + 1])?;
        }
        Some(StoreId(b))
    }

    /// Marker file bytes: `crumb-coord-store-id/1 <hex>\n`.
    pub fn encode(&self) -> Vec<u8> {
        format!("{STORE_ID_FORMAT} {}\n", self.to_hex()).into_bytes()
    }

    /// Parse marker file bytes. Anything but the exact v1 line is an error string.
    pub fn decode(bytes: &[u8]) -> Result<StoreId, String> {
        let s = std::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
        let line = s
            .strip_suffix('\n')
            .ok_or_else(|| "no trailing newline (torn or foreign file)".to_string())?;
        let (tag, hex) = line
            .split_once(' ')
            .ok_or_else(|| "expected `<format> <id>`".to_string())?;
        if tag != STORE_ID_FORMAT {
            return Err(format!("unsupported format {tag:?}"));
        }
        StoreId::parse_hex(hex).ok_or_else(|| format!("bad id {hex:?}"))
    }
}

impl std::fmt::Display for StoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for StoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreId({})", self.to_hex())
    }
}

/// Read `<root>/STORE_ID`. `Ok(None)` when absent.
pub(crate) fn read_marker(root: &Path) -> Result<Option<StoreId>, CoordError> {
    let p = root.join(STORE_ID_FILE);
    // Bounded, non-blocking, never following a link (issue #58): a FIFO, device, symlink or
    // oversized file as `STORE_ID` is a typed `RefusedRecord`, never a hang.
    match crate::record::read_bounded(&p, crate::MAX_MARKER_BYTES)? {
        Some(b) => StoreId::decode(&b)
            .map(Some)
            .map_err(|reason| CoordError::StoreIdUnreadable { path: p, reason }),
        None => Ok(None),
    }
}

/// Create the marker if absent and return the store's id. Call only while holding the
/// store's transaction lock (in-process mutex plus `fcntl` on `.lock`), so concurrent first
/// opens agree on one id. On top of the lock, the marker is published with `link(2)`, which
/// never replaces an existing file, so even a writer outside the lock cannot overwrite it.
/// A crash before the link leaves only a `STORE_ID.tmp<pid>` file and no marker.
pub(crate) fn ensure_marker_locked(root: &Path) -> Result<StoreId, CoordError> {
    if let Some(id) = read_marker(root)? {
        return Ok(id);
    }
    let p = root.join(STORE_ID_FILE);
    let tmp = root.join(format!("{STORE_ID_FILE}.tmp{}", std::process::id()));
    let id = StoreId::random().map_err(|source| CoordError::Io {
        path: PathBuf::from("/dev/urandom"),
        source,
    })?;
    {
        use std::io::Write;
        let mut f = crate::record::create_temp(&tmp)?;
        f.write_all(&id.encode()).map_err(crate::io_err(&tmp))?;
        f.sync_all().map_err(crate::io_err(&tmp))?;
    }
    crate::fault_point("storeid-before-link");
    let linked = std::fs::hard_link(&tmp, &p);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(CoordError::Io { path: p, source }),
    }
    crate::fsync_dir(root);
    read_marker(root)?.ok_or(CoordError::StoreIdMissing {
        root: root.to_path_buf(),
    })
}

/// Which input decided the coordination root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSource {
    /// `CRUMB_COORD_ROOT`, non-empty.
    Env,
    /// `git config --get crumb.coordinationRoot`, non-empty.
    GitConfig,
    /// `<git-common-dir>/crumb/v1`.
    GitCommonDir,
}

/// A coordination root as crumb.c would choose it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRoot {
    pub path: PathBuf,
    pub source: RootSource,
}

/// crumb.c reads `git` output into a 512-byte buffer, so it keeps at most this many bytes.
pub const GIT_OUTPUT_MAX: usize = 511;

/// Mirror of crumb.c `plane_resolve` (29780e5) root order, as a pure function: the caller
/// supplies the three inputs (this crate never runs Git).
///
/// 1. `env` = `CRUMB_COORD_ROOT`; used as given when non-empty.
/// 2. `git_config` = raw output of `git config --get crumb.coordinationRoot`; trailing `\n`
///    and `\r` are stripped as crumb.c does, then used as given when non-empty.
/// 3. `git_common_dir` = the repository's common directory, already made absolute and
///    `realpath`-resolved (crumb.c resolves `git rev-parse --git-common-dir` against the
///    working directory and calls `realpath`); the root is `<it>/crumb/v1`.
///
/// crumb.c does not canonicalize values from 1 or 2, so a relative value there means
/// "relative to the crumb process's working directory"; it is returned unchanged. A config
/// value of [`GIT_OUTPUT_MAX`] bytes or more is refused: crumb.c would silently truncate it
/// and pick a different directory. A relative common directory is refused (it cannot be
/// resolved without the filesystem).
pub fn resolve_coord_root(
    env: Option<&OsStr>,
    git_config: Option<&str>,
    git_common_dir: Option<&Path>,
) -> Result<ResolvedRoot, CoordError> {
    if let Some(e) = env.filter(|e| !e.is_empty()) {
        return Ok(ResolvedRoot {
            path: PathBuf::from(e),
            source: RootSource::Env,
        });
    }
    if let Some(raw) = git_config {
        if raw.len() >= GIT_OUTPUT_MAX {
            return Err(CoordError::RootUnresolved(format!(
                "crumb.coordinationRoot is {} bytes; crumb.c truncates git output at {GIT_OUTPUT_MAX}",
                raw.len()
            )));
        }
        let v = raw.trim_end_matches(['\n', '\r']);
        if !v.is_empty() {
            return Ok(ResolvedRoot {
                path: PathBuf::from(v),
                source: RootSource::GitConfig,
            });
        }
    }
    match git_common_dir {
        Some(cd) if cd.is_absolute() => Ok(ResolvedRoot {
            path: cd.join("crumb/v1"),
            source: RootSource::GitCommonDir,
        }),
        Some(cd) => Err(CoordError::RootUnresolved(format!(
            "git common directory {} is relative; pass it resolved (realpath)",
            cd.display()
        ))),
        None => Err(CoordError::RootUnresolved(
            "no CRUMB_COORD_ROOT, no crumb.coordinationRoot, and no git common directory".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_marker_round_trip() {
        let id = StoreId::random().unwrap();
        assert_eq!(StoreId::parse_hex(&id.to_hex()), Some(id));
        assert_eq!(StoreId::decode(&id.encode()), Ok(id));
        assert_ne!(StoreId::random().unwrap(), id);
        assert!(StoreId::parse_hex("0123456789ABCDEF0123456789abcdef").is_none());
        assert!(StoreId::parse_hex("0123456789abcdef0123456789abcde").is_none());
    }

    #[test]
    fn marker_decode_refuses_foreign_or_torn() {
        let id = StoreId::random().unwrap();
        let good = id.encode();
        assert!(StoreId::decode(&good[..good.len() - 1]).is_err(), "torn");
        let v2 = format!("crumb-coord-store-id/2 {}\n", id.to_hex());
        assert!(StoreId::decode(v2.as_bytes()).is_err(), "future format");
        assert!(StoreId::decode(b"crumb-coord-store-id/1 xyz\n").is_err());
        assert!(StoreId::decode(b"{}\n").is_err());
        assert!(StoreId::decode(&[0xff, b'\n']).is_err());
    }

    #[test]
    fn root_resolution_order_matches_crumb_c() {
        let cd = Path::new("/repo/.git");
        let r = |e: Option<&str>, c: Option<&str>, d: Option<&Path>| {
            resolve_coord_root(e.map(OsStr::new), c, d)
        };
        let env = r(Some("/e"), Some("/c\n"), Some(cd)).unwrap();
        assert_eq!(
            (env.path.as_path(), env.source),
            (Path::new("/e"), RootSource::Env)
        );
        let cfg = r(Some(""), Some("/c\r\n"), Some(cd)).unwrap();
        assert_eq!(
            (cfg.path.as_path(), cfg.source),
            (Path::new("/c"), RootSource::GitConfig)
        );
        let def = r(None, Some("\n"), Some(cd)).unwrap();
        assert_eq!(
            (def.path.as_path(), def.source),
            (Path::new("/repo/.git/crumb/v1"), RootSource::GitCommonDir)
        );
        assert_eq!(
            r(None, Some("rel/store"), None).unwrap().path,
            PathBuf::from("rel/store"),
            "relative config value is kept as crumb.c keeps it"
        );
        assert!(r(None, None, Some(Path::new(".git"))).is_err());
        assert!(r(None, None, None).is_err());
        let long = format!("/{}", "x".repeat(GIT_OUTPUT_MAX));
        assert!(r(None, Some(&long), Some(cd)).is_err());
    }
}
