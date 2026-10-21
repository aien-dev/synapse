//! Wake notification: a best-effort datagram per post, so a waiting agent needs no polling.
//!
//! A watcher binds `wake/<16 hex>.sock` (the hash of its tag: a board root plus a 64-byte
//! tag would not fit the 108-byte `sockaddr_un`). After a post is durable and its lock is
//! released, the writer sends the 8-byte little-endian event id to every wake socket on the
//! board (at most [`MAX_WAKE_FANOUT`], non-blocking). A datagram is only a hint: a lost,
//! dropped or never-sent wake costs latency (the waiter times out and reads), never an
//! event, because the journal and the cursor are the only truth. A wake spends no model
//! token; the reading agent still has to run to act on what it reads.

use super::frame::key_hash;
use super::journal::ensure_dir;
use super::{io_err, Board, BoardError, Resume};
use crate::record::{refusal_for, RecordRefusal};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Most wake sockets a single post signals.
pub const MAX_WAKE_FANOUT: usize = 256;
const H_WAKE: u8 = b'w';
/// `sockaddr_un.sun_path` is 108 bytes including the terminating NUL.
const MAX_SUN_PATH: usize = 107;

/// Result of a wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// A post happened (the highest id named by the datagrams drained, or by the read
    /// that found undelivered events). Read the board to see what is yours.
    Woke(u64),
    /// Nothing arrived in time. Reading is still correct (a datagram may have been lost).
    TimedOut,
}

/// A bound wake socket for one tag. Dropping it removes its socket file.
pub struct Watcher {
    tag: String,
    path: PathBuf,
    sock: UnixDatagram,
    ino: (u64, u64),
}

pub(crate) fn wake_path(root: &Path, tag: &str) -> PathBuf {
    root.join("wake")
        .join(format!("{:016x}.sock", key_hash(H_WAKE, tag.as_bytes())))
}

fn is_wake_name(n: &str) -> bool {
    n.len() == 21
        && n.ends_with(".sock")
        && n[..16]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Watcher {
    fn bind(board: &Board, tag: &str) -> Result<Watcher, BoardError> {
        ensure_dir(board.root(), "wake")?;
        let path = wake_path(board.root(), tag);
        if path.as_os_str().len() > MAX_SUN_PATH {
            return Err(BoardError::SocketPathTooLong { path });
        }
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                // A live watcher answers a connect; a stale file refuses it.
                let probe = UnixDatagram::unbound().map_err(io_err(&path))?;
                match probe.connect(&path) {
                    Ok(()) => {
                        return Err(BoardError::WatcherBusy {
                            tag: tag.into(),
                            path,
                        })
                    }
                    Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                        fs::remove_file(&path).map_err(io_err(&path))?;
                    }
                    Err(e) => return Err(io_err(&path)(e)),
                }
            }
            Ok(m) => {
                return Err(BoardError::Refused {
                    path,
                    reason: refusal_for(&m.file_type())
                        .unwrap_or(RecordRefusal::NotRegular("regular file")),
                })
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&path)(e)),
        }
        let sock = match UnixDatagram::bind(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                return Err(BoardError::WatcherBusy {
                    tag: tag.into(),
                    path,
                })
            }
            Err(e) => return Err(io_err(&path)(e)),
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(io_err(&path))?;
        let m = fs::symlink_metadata(&path).map_err(io_err(&path))?;
        Ok(Watcher {
            tag: tag.into(),
            path,
            sock,
            ino: (m.dev(), m.ino()),
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Block up to `timeout` for a wake datagram, then drain any queued ones.
    pub fn wait(&self, timeout: Duration) -> Result<Wake, BoardError> {
        let mut buf = [0u8; 16];
        let first = if timeout.is_zero() {
            self.sock
                .set_nonblocking(true)
                .map_err(io_err(&self.path))?;
            self.sock.recv(&mut buf)
        } else {
            self.sock
                .set_nonblocking(false)
                .map_err(io_err(&self.path))?;
            self.sock
                .set_read_timeout(Some(timeout))
                .map_err(io_err(&self.path))?;
            self.sock.recv(&mut buf)
        };
        let mut best = match first {
            Ok(n) => datagram_id(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(Wake::TimedOut)
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => return Ok(Wake::TimedOut),
            Err(e) => return Err(io_err(&self.path)(e)),
        };
        self.sock
            .set_nonblocking(true)
            .map_err(io_err(&self.path))?;
        // Bounded drain: at most one fanout's worth per wait.
        for _ in 0..MAX_WAKE_FANOUT * 4 {
            match self.sock.recv(&mut buf) {
                Ok(n) => best = best.max(datagram_id(&buf[..n])),
                Err(_) => break,
            }
        }
        Ok(Wake::Woke(best))
    }
}

/// A malformed datagram (anyone who can write the board can send one) still wakes, with id 0.
fn datagram_id(b: &[u8]) -> u64 {
    match <[u8; 8]>::try_from(b) {
        Ok(a) => u64::from_le_bytes(a),
        Err(_) => 0,
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Ok(m) = fs::symlink_metadata(&self.path) {
            if (m.dev(), m.ino()) == self.ino {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Send `id` to every wake socket under `root/wake` (best effort, non-blocking). Returns the
/// number of datagrams accepted by the kernel.
pub(crate) fn wake_all(root: &Path, id: u64) -> usize {
    let Ok(rd) = fs::read_dir(root.join("wake")) else {
        return 0;
    };
    let Ok(tx) = UnixDatagram::unbound() else {
        return 0;
    };
    if tx.set_nonblocking(true).is_err() {
        return 0;
    }
    let msg = id.to_le_bytes();
    let mut tried = 0;
    let mut sent = 0;
    for ent in rd.filter_map(|e| e.ok()) {
        if tried == MAX_WAKE_FANOUT {
            break;
        }
        let name = ent.file_name();
        let Some(n) = name.to_str() else { continue };
        if !is_wake_name(n) {
            continue;
        }
        let p = ent.path();
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_socket() => {}
            _ => continue,
        }
        tried += 1;
        if tx.send_to(&msg, &p).is_ok() {
            sent += 1;
        }
    }
    sent
}

impl Board {
    /// Bind this session's wake socket. Bind before reading, then wait: a post that lands
    /// between the read and the wait still wakes the socket.
    pub fn watcher(&self, session: &str) -> Result<Watcher, BoardError> {
        let me = self.whoami(session)?;
        Watcher::bind(self, &me.tag)
    }

    /// Wait up to `timeout` for something new for this session. Returns `Woke` at once when
    /// events past the `delivered` cursor are already visible to it; otherwise binds the
    /// wake socket for the duration of the call and blocks on it. Race-free: the socket is
    /// bound before the check.
    pub fn wait(&self, session: &str, timeout: Duration) -> Result<Wake, BoardError> {
        let w = self.watcher(session)?;
        if let Some(id) = self.first_undelivered(session)? {
            return Ok(Wake::Woke(id));
        }
        w.wait(timeout)
    }

    /// The first event past the `delivered` cursor visible to this session, if any (pure).
    fn first_undelivered(&self, session: &str) -> Result<Option<u64>, BoardError> {
        let me = self.whoami(session)?;
        let mut after = self.start_after(&me.tag, Resume::Delivered)?;
        loop {
            let b = self.read_since(session, after, 64)?;
            if let Some(d) = b.events.first() {
                return Ok(Some(d.event.id));
            }
            if !b.more || b.through <= after {
                return Ok(None);
            }
            after = b.through;
        }
    }
}
