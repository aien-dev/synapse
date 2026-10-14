//! Bounded, non-blocking reads of store files (issue #58).
//!
//! Anyone who can write into the shared coordination store can plant a FIFO, a device, a
//! symlink to `/dev/zero`, or a huge file under a record name. A plain `fs::read` blocks
//! forever on the first and reads without limit on the others, so one hostile entry would
//! stop every reader (and the pre-submit advisory, which must always answer). Every store
//! file read goes through [`read_bounded`] instead:
//!
//! 1. `lstat` the name; anything that is not a regular file is refused without opening it
//!    (a FIFO, socket or device is never opened, so opening can have no side effect);
//! 2. open with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` (a symlink swapped in after step 1
//!    fails with `ELOOP`; a FIFO swapped in cannot block the open);
//! 3. `fstat` the opened descriptor and refuse anything that is not a regular file;
//! 4. read at most `cap + 1` bytes and refuse the record if more than `cap` arrive.
//!
//! A refusal is a typed [`CoordError::RefusedRecord`], handled exactly like
//! [`CoordError::CorruptRecord`]: the operation fails, nothing is written, the file is left
//! as found, and the read-only advisory reports `Unavailable`.

use crate::CoordError;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

/// Largest coordination record (`dirs/*.json`, `agents/*.json`) that is read: 1 MiB.
/// crumb.c records are a few KiB (20 history entries, locks, whispers of the last 24 h).
/// A record that would exceed this is refused on write as well, so this crate never creates
/// a record it would later refuse to read.
pub const MAX_RECORD_BYTES: u64 = 1 << 20;

/// Largest `STORE_ID` marker that is read. A v1 marker is under 100 bytes.
pub const MAX_MARKER_BYTES: u64 = 4096;

/// Why a store file was refused without being parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordRefusal {
    /// The name is a symbolic link. Records are never followed (crumb.c follows them; a
    /// link to `/dev/zero` or a FIFO elsewhere would stall every reader).
    Symlink,
    /// The name is not a regular file: `"fifo"`, `"socket"`, `"char device"`,
    /// `"block device"` or `"directory"`.
    NotRegular(&'static str),
    /// The file is larger than `limit` bytes.
    TooLarge { limit: u64 },
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordRefusal::Symlink => write!(f, "is a symbolic link"),
            RecordRefusal::NotRegular(k) => write!(f, "is a {k}, not a regular file"),
            RecordRefusal::TooLarge { limit } => write!(f, "is larger than {limit} bytes"),
        }
    }
}

pub(crate) fn refusal_for(ft: &fs::FileType) -> Option<RecordRefusal> {
    if ft.is_file() {
        None
    } else if ft.is_symlink() {
        Some(RecordRefusal::Symlink)
    } else if ft.is_fifo() {
        Some(RecordRefusal::NotRegular("fifo"))
    } else if ft.is_socket() {
        Some(RecordRefusal::NotRegular("socket"))
    } else if ft.is_char_device() {
        Some(RecordRefusal::NotRegular("char device"))
    } else if ft.is_block_device() {
        Some(RecordRefusal::NotRegular("block device"))
    } else if ft.is_dir() {
        Some(RecordRefusal::NotRegular("directory"))
    } else {
        Some(RecordRefusal::NotRegular("special file"))
    }
}

fn refused(path: &Path, reason: RecordRefusal) -> CoordError {
    CoordError::RefusedRecord {
        path: path.to_path_buf(),
        reason,
    }
}

fn io(path: &Path, source: std::io::Error) -> CoordError {
    CoordError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Read a store file of at most `cap` bytes without following links or blocking.
/// `Ok(None)` when the name does not exist.
pub(crate) fn read_bounded(path: &Path, cap: u64) -> Result<Option<Vec<u8>>, CoordError> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            if let Some(r) = refusal_for(&m.file_type()) {
                return Err(refused(path, r));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(path, e)),
    }
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refused(path, RecordRefusal::Symlink))
        }
        Err(e) => return Err(io(path, e)),
    };
    let m = f.metadata().map_err(|e| io(path, e))?;
    if let Some(r) = refusal_for(&m.file_type()) {
        return Err(refused(path, r));
    }
    if m.len() > cap {
        return Err(refused(path, RecordRefusal::TooLarge { limit: cap }));
    }
    let mut buf = Vec::with_capacity(m.len() as usize);
    (&f as &File)
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io(path, e))?;
    if buf.len() as u64 > cap {
        return Err(refused(path, RecordRefusal::TooLarge { limit: cap }));
    }
    Ok(Some(buf))
}

/// Refuse to replace `path` unless it is absent or a regular file (a rename would silently
/// swap a planted FIFO or symlink for a record; refuse instead, like a corrupt record).
pub(crate) fn check_replaceable(path: &Path) -> Result<(), CoordError> {
    match fs::symlink_metadata(path) {
        Ok(m) => match refusal_for(&m.file_type()) {
            Some(r) => Err(refused(path, r)),
            None => Ok(()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(path, e)),
    }
}

/// Create a fresh temporary file for a durable write. Whatever already has that name (a
/// stale temp from a crashed writer with the same pid, or a planted FIFO or symlink) is
/// unlinked first, never opened, and the new file is created with `O_EXCL | O_NOFOLLOW`, so
/// the write can neither block on a FIFO nor follow a link to somewhere else.
pub(crate) fn create_temp(tmp: &Path) -> Result<File, CoordError> {
    match fs::remove_file(tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(tmp, e)),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(tmp)
        .map_err(|e| io(tmp, e))
}
