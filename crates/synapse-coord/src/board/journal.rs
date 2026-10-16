//! The journal: writer lock, `BOARD_ID`, append with fsync before ACK, the torn-tail rule,
//! bounded storage, explicit compaction and the read-only consistency check.
//!
//! **Commit order of one post** (all under the `fcntl` writer lock on `<root>/.lock`):
//!
//! 1. append the frame to `journal.log`, `fdatasync` it;
//! 2. append the id to `topics/<topic>.idx` and to `inbox/<tag>.idx` of every addressee,
//!    `fdatasync` them together (one fsync group, issued in parallel);
//! 3. write the 64-byte entry at `(id - base) * 64` of `journal.idx`, `fdatasync` it. This
//!    entry is the commit point: readers only see ids up to the last valid entry, and every
//!    index they consult was durable before it;
//! 4. release the lock, return the receipt (the ACK), then send best-effort wake datagrams.
//!
//! **Torn-tail rule.** Bytes in `journal.log` after the last frame named by `journal.idx`
//! belong to a post that was never acknowledged. The next writer (and only a writer, under
//! the lock) reconciles them: a complete frame that verifies (length, CRC-32C, JSON body,
//! next id, this mission) is adopted with its id (so a retry with the same idempotency key
//! finds it); anything else is the torn tail and is truncated, reported as
//! [`Recovery::torn_tail_at`]. More than one frame's worth of unverifiable bytes is not a
//! torn tail: it is refused as [`BoardError::Corrupt`], never guessed past. Readers never
//! truncate; they stop at the commit point.

use super::frame::{
    self, corrupt, key_hash, Entry, ENTRY_BYTES, FRAME_HEADER, H_IDEM, H_THREAD, H_TOPIC, ID_BYTES,
    MAX_FRAME_BYTES,
};
use super::{io_err, Board, BoardError, BoardId, Event, Me, Post, BOARD_ID_FILE, BOARD_ID_FORMAT};
use crate::record::{refusal_for, RecordRefusal};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

pub(crate) const JOURNAL: &str = "journal.log";
pub(crate) const TABLE: &str = "journal.idx";
pub(crate) const SUBDIRS: [&str; 6] = ["topics", "inbox", "agents", "subs", "cursors", "wake"];

/// Unverifiable bytes after the commit point larger than this are corruption, not a torn
/// tail (a torn tail is at most one partly written frame).
const MAX_TORN: u64 = FRAME_HEADER + MAX_FRAME_BYTES as u64;

/// Test-only fault injection, shared with the coordination store: `SYNAPSE_COORD_FAULT=<p>`.
fn fault(point: &str) {
    crate::fault_point(point);
}

pub(crate) fn fault_active(point: &str) -> bool {
    std::env::var("SYNAPSE_COORD_FAULT").as_deref() == Ok(point)
}

fn refused(path: &Path, reason: RecordRefusal) -> BoardError {
    BoardError::Refused {
        path: path.to_path_buf(),
        reason,
    }
}

/// Open an existing board file read-only without following a link or blocking on a FIFO
/// (the [`crate::record`] rules): `lstat` first, a non-regular name is never opened.
pub(crate) fn open_ro(path: &Path) -> Result<Option<File>, BoardError> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            if let Some(r) = refusal_for(&m.file_type()) {
                return Err(refused(path, r));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(path)(e)),
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
        Err(e) => return Err(io_err(path)(e)),
    };
    let m = f.metadata().map_err(io_err(path))?;
    if let Some(r) = refusal_for(&m.file_type()) {
        return Err(refused(path, r));
    }
    Ok(Some(f))
}

/// Open (creating if absent) a board file for writing, with the same refusals. Returns
/// whether it was created (its directory then needs an fsync).
pub(crate) fn open_rw(root: &Path, path: &Path) -> Result<(File, bool), BoardError> {
    crate::record::check_real_parents(root, path)?;
    let created = match fs::symlink_metadata(path) {
        Ok(m) => {
            if let Some(r) = refusal_for(&m.file_type()) {
                return Err(refused(path, r));
            }
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(io_err(path)(e)),
    };
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => refused(path, RecordRefusal::Symlink),
            Some(libc::ENXIO) => refused(path, RecordRefusal::NotRegular("fifo")),
            Some(libc::EISDIR) => refused(path, RecordRefusal::NotRegular("directory")),
            _ => io_err(path)(e),
        })?;
    let m = f.metadata().map_err(io_err(path))?;
    if let Some(r) = refusal_for(&m.file_type()) {
        return Err(refused(path, r));
    }
    Ok((f, created))
}

/// Make `<root>/<name>` a real directory (a symlink or file planted there is refused).
pub(crate) fn ensure_dir(root: &Path, name: &str) -> Result<PathBuf, BoardError> {
    let d = root.join(name);
    match fs::symlink_metadata(&d) {
        Ok(m) if m.file_type().is_dir() => return Ok(d),
        Ok(m) => {
            return Err(refused(
                &d,
                refusal_for(&m.file_type()).unwrap_or(RecordRefusal::NotDirectory),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&d)(e)),
    }
    match fs::create_dir(&d) {
        Ok(()) => crate::fsync_dir(root),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_err(&d)(e)),
    }
    match fs::symlink_metadata(&d) {
        Ok(m) if m.file_type().is_dir() => Ok(d),
        _ => Err(refused(&d, RecordRefusal::NotDirectory)),
    }
}

pub(crate) fn fsync_dir(d: &Path) {
    crate::fsync_dir(d)
}

/// A process-wide mutex plus an `fcntl` write lock on one lock file, the pattern of the
/// coordination store's transaction lock (POSIX record locks belong to the process, so
/// threads are serialised by the mutex and processes by `fcntl`).
pub(crate) struct FileLock {
    _file: File,
    _guard: MutexGuard<'static, ()>,
}

pub(crate) fn fcntl_lock(
    root: &Path,
    lp: &Path,
    mutex: &'static Mutex<()>,
) -> Result<FileLock, BoardError> {
    let guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
    let (f, _) = open_rw(root, lp)?;
    // SAFETY: a zeroed flock is a valid "whole file from offset 0" request.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;
    loop {
        // SAFETY: f is open for the duration of the call; fl is a valid flock.
        let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLKW, &fl) };
        if rc == 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(io_err(lp)(e));
        }
    }
    Ok(FileLock {
        _file: f,
        _guard: guard,
    })
}

static WRITER: Mutex<()> = Mutex::new(());

/// The board writer lock on `<root>/.lock`.
pub(crate) struct BoardLock(#[allow(dead_code)] FileLock);
impl BoardLock {
    pub fn acquire(root: &Path) -> Result<BoardLock, BoardError> {
        Ok(BoardLock(fcntl_lock(root, &root.join(".lock"), &WRITER)?))
    }
}

/// A coordination store (`STORE_ID`, `dirs/`) is never a board root: the two would share
/// a `.lock` and an operator could mistake one for the other.
pub(crate) fn refuse_coord_root(root: &Path) -> Result<(), BoardError> {
    for n in [crate::STORE_ID_FILE, "dirs"] {
        if fs::symlink_metadata(root.join(n)).is_ok() {
            return Err(BoardError::NotABoard {
                root: root.to_path_buf(),
                reason: format!("it has {n}, so it is a Crumb coordination store"),
            });
        }
    }
    Ok(())
}

fn encode_board_id(id: &BoardId) -> Vec<u8> {
    format!("{BOARD_ID_FORMAT} {}\n", id.to_hex()).into_bytes()
}

fn decode_board_id(b: &[u8]) -> Result<BoardId, String> {
    let s = std::str::from_utf8(b).map_err(|_| "not UTF-8".to_string())?;
    let line = s
        .strip_suffix('\n')
        .ok_or_else(|| "no trailing newline (torn or foreign file)".to_string())?;
    let (tag, hex) = line
        .split_once(' ')
        .ok_or_else(|| "expected `<format> <id>`".to_string())?;
    if tag != BOARD_ID_FORMAT {
        return Err(format!("unsupported format {tag:?}"));
    }
    BoardId::parse_hex(hex).ok_or_else(|| format!("bad id {hex:?}"))
}

/// Read `<root>/BOARD_ID` (bounded, never following a link). `Ok(None)` when absent.
pub(crate) fn read_board_id(root: &Path) -> Result<Option<BoardId>, BoardError> {
    let p = root.join(BOARD_ID_FILE);
    match crate::record::read_bounded(&p, crate::MAX_MARKER_BYTES)? {
        Some(b) => decode_board_id(&b)
            .map(Some)
            .map_err(|reason| BoardError::BoardIdUnreadable { path: p, reason }),
        None => Ok(None),
    }
}

/// Create the marker if absent (caller holds the writer lock); published with `link(2)` so
/// it is never replaced, exactly like `STORE_ID`.
pub(crate) fn ensure_board_id_locked(root: &Path) -> Result<BoardId, BoardError> {
    if let Some(id) = read_board_id(root)? {
        return Ok(id);
    }
    let p = root.join(BOARD_ID_FILE);
    let tmp = root.join(format!("{BOARD_ID_FILE}.tmp{}", std::process::id()));
    let id = BoardId::random().map_err(io_err(Path::new("/dev/urandom")))?;
    {
        let mut f = crate::record::create_temp(&tmp)?;
        f.write_all(&encode_board_id(&id)).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
    }
    let linked = fs::hard_link(&tmp, &p);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_err(&p)(e)),
    }
    fsync_dir(root);
    read_board_id(root)?.ok_or(BoardError::BoardIdMissing {
        root: root.to_path_buf(),
    })
}

/// Why a frame at an offset did not verify.
enum FrameBad {
    Short,
    Length(u32),
    Checksum,
}

impl FrameBad {
    fn reason(&self) -> String {
        match self {
            FrameBad::Short => "frame runs past the end of the file".into(),
            FrameBad::Length(l) => format!("frame length {l} is over {MAX_FRAME_BYTES}"),
            FrameBad::Checksum => "frame checksum does not verify".into(),
        }
    }
}

/// A frame as read: `Ok((len, crc, body))` or why it does not verify.
type FrameRead = Result<(u32, u32, Vec<u8>), FrameBad>;

/// Read and verify the frame at `off` of a journal of length `flen`: `(len, crc, body)`.
fn read_frame(f: &File, path: &Path, off: u64, flen: u64) -> Result<FrameRead, BoardError> {
    if off + FRAME_HEADER > flen {
        return Ok(Err(FrameBad::Short));
    }
    let mut h = [0u8; FRAME_HEADER as usize];
    f.read_exact_at(&mut h, off).map_err(io_err(path))?;
    let len = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let crc = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    if len > MAX_FRAME_BYTES {
        return Ok(Err(FrameBad::Length(len)));
    }
    if off + FRAME_HEADER + len as u64 > flen {
        return Ok(Err(FrameBad::Short));
    }
    let mut body = vec![0u8; len as usize];
    f.read_exact_at(&mut body, off + FRAME_HEADER)
        .map_err(io_err(path))?;
    if frame::crc32c(&body) != crc {
        return Ok(Err(FrameBad::Checksum));
    }
    Ok(Ok((len, crc, body)))
}

fn entry_for(ev: &Event, offset: u64, len: u32, crc: u32) -> Entry {
    Entry {
        id: ev.id,
        offset,
        len,
        crc,
        topic_h: key_hash(H_TOPIC, ev.topic.as_bytes()),
        thread_h: key_hash(H_THREAD, ev.thread.as_bytes()),
        idem_h: ev
            .idem
            .as_deref()
            .map(|k| key_hash(H_IDEM, k.as_bytes()))
            .unwrap_or(0),
    }
}

pub(crate) fn topic_file(root: &Path, topic: &str) -> PathBuf {
    root.join("topics")
        .join(format!("{:016x}.idx", key_hash(H_TOPIC, topic.as_bytes())))
}

pub(crate) fn inbox_file(root: &Path, tag: &str) -> PathBuf {
    root.join("inbox").join(format!("{tag}.idx"))
}

/// A read-only view of the committed board, taken without the lock.
pub(crate) struct Snapshot {
    idx: Option<File>,
    journal: Option<File>,
    idx_path: PathBuf,
    j_path: PathBuf,
    mission: BoardId,
    /// Oldest kept id (0 when empty).
    pub base: u64,
    /// Last committed id (0 when empty).
    pub last: u64,
    /// Offset of a partly written or unverifiable final table entry (a post in flight).
    pub torn_entry: Option<u64>,
    jlen: u64,
}

impl Snapshot {
    pub fn take(board: &Board) -> Result<Snapshot, BoardError> {
        let root = board.root();
        let idx_path = root.join(TABLE);
        let j_path = root.join(JOURNAL);
        let idx = open_ro(&idx_path)?;
        let journal = open_ro(&j_path)?;
        let mut s = Snapshot {
            idx: None,
            journal: None,
            idx_path,
            j_path,
            mission: board.id(),
            base: 0,
            last: 0,
            torn_entry: None,
            jlen: 0,
        };
        let lim = board.limits();
        if let Some(j) = &journal {
            s.jlen = j.metadata().map_err(io_err(&s.j_path))?.len();
            if s.jlen > lim.max_journal_bytes + MAX_TORN {
                return Err(refused(
                    &s.j_path,
                    RecordRefusal::TooLarge {
                        limit: lim.max_journal_bytes + MAX_TORN,
                    },
                ));
            }
        }
        let Some(idx) = idx else {
            s.journal = journal;
            return Ok(s);
        };
        let ilen = idx.metadata().map_err(io_err(&s.idx_path))?.len();
        let cap = (lim.max_events + 1) * ENTRY_BYTES;
        if ilen > cap {
            return Err(refused(&s.idx_path, RecordRefusal::TooLarge { limit: cap }));
        }
        let mut n = ilen / ENTRY_BYTES;
        if ilen % ENTRY_BYTES != 0 {
            s.torn_entry = Some(n * ENTRY_BYTES);
        }
        if n == 0 {
            s.journal = journal;
            return Ok(s);
        }
        if journal.is_none() {
            return Err(corrupt(
                &s.j_path,
                0,
                "journal.idx names events but journal.log is missing",
            ));
        }
        let read = |i: u64| -> Result<Option<Entry>, BoardError> {
            let mut b = [0u8; ENTRY_BYTES as usize];
            idx.read_exact_at(&mut b, i * ENTRY_BYTES)
                .map_err(io_err(&s.idx_path))?;
            Ok(Entry::decode(&b))
        };
        let mut last_e = read(n - 1)?;
        if last_e.is_none() {
            s.torn_entry = Some((n - 1) * ENTRY_BYTES);
            n -= 1;
            if n == 0 {
                s.journal = journal;
                return Ok(s);
            }
            last_e = read(n - 1)?;
        }
        let le =
            last_e.ok_or_else(|| corrupt(&s.idx_path, (n - 1) * ENTRY_BYTES, "entry checksum"))?;
        let e0 = read(0)?.ok_or_else(|| corrupt(&s.idx_path, 0, "entry checksum"))?;
        if e0.id == 0 || le.id != e0.id + n - 1 {
            return Err(corrupt(&s.idx_path, 0, "table ids are not contiguous"));
        }
        s.base = e0.id;
        s.last = le.id;
        s.idx = Some(idx);
        s.journal = journal;
        Ok(s)
    }

    pub fn entry(&self, id: u64) -> Result<Entry, BoardError> {
        let idx = self.idx.as_ref().ok_or(BoardError::IndexMismatch { id })?;
        if id < self.base || id > self.last {
            return Err(BoardError::IndexMismatch { id });
        }
        let off = (id - self.base) * ENTRY_BYTES;
        let mut b = [0u8; ENTRY_BYTES as usize];
        idx.read_exact_at(&mut b, off)
            .map_err(io_err(&self.idx_path))?;
        let e = Entry::decode(&b).ok_or_else(|| corrupt(&self.idx_path, off, "entry checksum"))?;
        if e.id != id {
            return Err(corrupt(&self.idx_path, off, "entry id out of sequence"));
        }
        Ok(e)
    }

    /// Read and verify the event an entry names.
    pub fn event(&self, e: &Entry) -> Result<Event, BoardError> {
        let j = self
            .journal
            .as_ref()
            .ok_or(BoardError::IndexMismatch { id: e.id })?;
        match read_frame(j, &self.j_path, e.offset, self.jlen)? {
            Ok((len, crc, body)) => {
                if len != e.len || crc != e.crc {
                    return Err(BoardError::IndexMismatch { id: e.id });
                }
                let ev = Event::from_body(&body).map_err(|r| corrupt(&self.j_path, e.offset, r))?;
                if ev.id != e.id {
                    return Err(BoardError::IndexMismatch { id: e.id });
                }
                if ev.mission != self.mission {
                    return Err(BoardError::ForeignMission {
                        id: ev.id,
                        found: ev.mission,
                    });
                }
                Ok(ev)
            }
            Err(FrameBad::Short) if e.frame_end() > self.jlen => {
                // The table names bytes the journal does not have: a swapped-in compaction
                // seen half-way, or a truncated journal (persisting means corruption).
                Err(BoardError::IndexMismatch { id: e.id })
            }
            Err(b) => Err(corrupt(&self.j_path, e.offset, b.reason())),
        }
    }

    pub fn get(&self, id: u64) -> Result<Event, BoardError> {
        let e = self.entry(id)?;
        self.event(&e)
    }

    /// Visit entries `from..=last` in order until `f` returns false.
    pub fn scan(
        &self,
        from: u64,
        mut f: impl FnMut(&Entry) -> Result<bool, BoardError>,
    ) -> Result<(), BoardError> {
        let Some(idx) = &self.idx else { return Ok(()) };
        let mut id = from.max(self.base);
        const CHUNK: u64 = 256;
        while id <= self.last {
            let n = CHUNK.min(self.last - id + 1);
            let mut buf = vec![0u8; (n * ENTRY_BYTES) as usize];
            let off = (id - self.base) * ENTRY_BYTES;
            idx.read_exact_at(&mut buf, off)
                .map_err(io_err(&self.idx_path))?;
            for (k, c) in buf
                .as_chunks::<{ ENTRY_BYTES as usize }>()
                .0
                .iter()
                .enumerate()
            {
                let at = off + k as u64 * ENTRY_BYTES;
                let e = Entry::decode(c)
                    .ok_or_else(|| corrupt(&self.idx_path, at, "entry checksum"))?;
                if e.id != id + k as u64 {
                    return Err(corrupt(&self.idx_path, at, "entry id out of sequence"));
                }
                if !f(&e)? {
                    return Ok(());
                }
            }
            id += n;
        }
        Ok(())
    }
}

/// Ids in an index file `(after, last]`, at most `limit`, plus whether more were left.
pub(crate) fn read_ids_after(
    path: &Path,
    after: u64,
    last: u64,
    limit: usize,
    max_events: u64,
) -> Result<(Vec<u64>, bool), BoardError> {
    let Some(f) = open_ro(path)? else {
        return Ok((Vec::new(), false));
    };
    let len = f.metadata().map_err(io_err(path))?.len();
    let cap = (max_events + 1) * ID_BYTES * 4;
    if len > cap {
        return Err(refused(path, RecordRefusal::TooLarge { limit: cap }));
    }
    let n = len / ID_BYTES;
    let at = |i: u64| -> Result<u64, BoardError> {
        let mut b = [0u8; 8];
        f.read_exact_at(&mut b, i * ID_BYTES)
            .map_err(io_err(path))?;
        Ok(u64::from_le_bytes(b))
    };
    // First position whose id is > after (ids are strictly increasing; checked below).
    let (mut lo, mut hi) = (0u64, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if at(mid)? <= after {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut out = Vec::new();
    let mut prev = if lo > 0 { at(lo - 1)? } else { 0 };
    let mut i = lo;
    while i < n {
        let id = at(i)?;
        if id <= prev {
            return Err(corrupt(path, i * ID_BYTES, "index ids are not increasing"));
        }
        if id > last {
            break;
        }
        if out.len() == limit {
            return Ok((out, true));
        }
        out.push(id);
        prev = id;
        i += 1;
    }
    Ok((out, false))
}

/// Append `id` to an id index unless it is already its last entry. A partly written final
/// entry is dropped first.
fn append_id(path: &Path, f: &File, id: u64) -> Result<bool, BoardError> {
    let mut len = f.metadata().map_err(io_err(path))?.len();
    if len % ID_BYTES != 0 {
        len -= len % ID_BYTES;
        f.set_len(len).map_err(io_err(path))?;
    }
    if len >= ID_BYTES {
        let mut b = [0u8; 8];
        f.read_exact_at(&mut b, len - ID_BYTES)
            .map_err(io_err(path))?;
        let last = u64::from_le_bytes(b);
        if last == id {
            return Ok(false);
        }
        if last > id {
            return Err(corrupt(
                path,
                len - ID_BYTES,
                format!("index already lists {last} > {id}"),
            ));
        }
    }
    f.write_all_at(&id.to_le_bytes(), len)
        .map_err(io_err(path))?;
    Ok(true)
}

/// `fdatasync` a group of files, in parallel threads (one journal commit can cover them).
fn sync_group(files: &[(&Path, &File)]) -> Result<(), BoardError> {
    if files.len() <= 1 {
        for (p, f) in files {
            f.sync_data().map_err(io_err(p))?;
        }
        return Ok(());
    }
    std::thread::scope(|s| {
        let hs: Vec<_> = files
            .iter()
            .map(|(p, f)| s.spawn(move || f.sync_data().map_err(io_err(p))))
            .collect();
        hs.into_iter()
            .zip(files.iter())
            .map(|(h, (p, _))| match h.join() {
                Ok(r) => r,
                Err(_) => Err(BoardError::Io {
                    path: p.to_path_buf(),
                    source: std::io::Error::other("fsync thread panicked"),
                }),
            })
            .collect::<Result<Vec<()>, BoardError>>()
    })?;
    Ok(())
}

/// What the writer reconciled before its own append.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// A torn (unacknowledged, unverifiable) tail was truncated at this journal offset.
    pub torn_tail_at: Option<u64>,
    pub torn_bytes: u64,
    /// Complete frames after the commit point (posts that crashed before their ACK) were
    /// adopted with these ids.
    pub adopted: Vec<u64>,
    /// A partly written final `journal.idx` entry was dropped.
    pub dropped_table_entry: bool,
    /// `journal.idx` disagreed with `journal.log` (a compaction cut between its renames)
    /// and was rebuilt from the journal.
    pub table_rebuilt: bool,
}

impl Recovery {
    pub fn is_empty(&self) -> bool {
        *self == Recovery::default()
    }
}

/// The receipt of a post: returned only after the fsync group, so it is the ACK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostReceipt {
    pub id: u64,
    pub mission: BoardId,
    /// True when an earlier event with the same idempotency key and body was returned.
    pub dedup: bool,
    pub recovery: Recovery,
    /// Wake datagrams delivered (best effort).
    pub woke: usize,
}

struct Writer<'a> {
    board: &'a Board,
    _lock: BoardLock,
    j: File,
    jp: PathBuf,
    idx: File,
    ip: PathBuf,
    base: u64,
    last: u64,
    end: u64,
    rec: Recovery,
}

impl<'a> Writer<'a> {
    fn open(board: &'a Board) -> Result<Writer<'a>, BoardError> {
        let root = board.root();
        let lock = BoardLock::acquire(root)?;
        board.check_id_locked()?;
        for d in SUBDIRS {
            ensure_dir(root, d)?;
        }
        let jp = root.join(JOURNAL);
        let ip = root.join(TABLE);
        let (j, jc) = open_rw(root, &jp)?;
        let (idx, ic) = open_rw(root, &ip)?;
        if jc || ic {
            fsync_dir(root);
        }
        let mut w = Writer {
            board,
            _lock: lock,
            j,
            jp,
            idx,
            ip,
            base: 0,
            last: 0,
            end: 0,
            rec: Recovery::default(),
        };
        w.recover()?;
        Ok(w)
    }

    fn jlen(&self) -> Result<u64, BoardError> {
        Ok(self.j.metadata().map_err(io_err(&self.jp))?.len())
    }

    fn table_entry(&self, i: u64) -> Result<Option<Entry>, BoardError> {
        let mut b = [0u8; ENTRY_BYTES as usize];
        self.idx
            .read_exact_at(&mut b, i * ENTRY_BYTES)
            .map_err(io_err(&self.ip))?;
        Ok(Entry::decode(&b))
    }

    /// True when the frame at `e.offset` is exactly the one `e` names.
    fn frame_matches(&self, e: &Entry, jlen: u64) -> Result<bool, BoardError> {
        Ok(match read_frame(&self.j, &self.jp, e.offset, jlen)? {
            Ok((len, crc, body)) => {
                len == e.len && crc == e.crc && Event::from_body(&body).map(|ev| ev.id) == Ok(e.id)
            }
            Err(_) => false,
        })
    }

    fn recover(&mut self) -> Result<(), BoardError> {
        let jlen = self.jlen()?;
        let mut ilen = self.idx.metadata().map_err(io_err(&self.ip))?.len();
        if ilen % ENTRY_BYTES != 0 {
            ilen -= ilen % ENTRY_BYTES;
            self.idx.set_len(ilen).map_err(io_err(&self.ip))?;
            self.rec.dropped_table_entry = true;
        }
        let mut n = ilen / ENTRY_BYTES;
        if n > 0 && self.table_entry(n - 1)?.is_none() {
            n -= 1;
            self.idx
                .set_len(n * ENTRY_BYTES)
                .map_err(io_err(&self.ip))?;
            self.rec.dropped_table_entry = true;
        }
        if n > 0 {
            let e0 = self.table_entry(0)?;
            let le = self.table_entry(n - 1)?;
            match (e0, le) {
                (Some(e0), Some(le))
                    if e0.offset == 0
                        && e0.id > 0
                        && le.id == e0.id + n - 1
                        && self.frame_matches(&e0, jlen)? =>
                {
                    // Same generation. The last committed frame must be intact: acknowledged
                    // events would be lost by any repair, so a mismatch is refused.
                    if le.frame_end() > jlen || !self.frame_matches(&le, jlen)? {
                        return Err(corrupt(
                            &self.jp,
                            le.offset,
                            format!(
                                "committed event {} does not verify (journal truncated or overwritten); refusing",
                                le.id
                            ),
                        ));
                    }
                    self.base = e0.id;
                    self.last = le.id;
                    self.end = le.frame_end();
                }
                _ => {
                    // The table belongs to another journal generation (a compaction cut
                    // between its two renames) or is unreadable: rebuild it from the
                    // journal, which is the truth.
                    self.idx.set_len(0).map_err(io_err(&self.ip))?;
                    self.rec.table_rebuilt = true;
                }
            }
        }
        self.scan_tail(jlen)
    }

    /// Reconcile bytes after the commit point (see the torn-tail rule above).
    fn scan_tail(&mut self, jlen: u64) -> Result<(), BoardError> {
        let mut adopted: Vec<(Event, Entry)> = Vec::new();
        let mut pos = self.end;
        let mut expect = if self.last == 0 {
            None
        } else {
            Some(self.last + 1)
        };
        while pos < jlen {
            let bad = match read_frame(&self.j, &self.jp, pos, jlen)? {
                Ok((len, crc, body)) => match Event::from_body(&body) {
                    Ok(ev) if expect.is_none_or(|x| x == ev.id) => {
                        if ev.mission != self.board.id() {
                            return Err(BoardError::ForeignMission {
                                id: ev.id,
                                found: ev.mission,
                            });
                        }
                        let e = entry_for(&ev, pos, len, crc);
                        expect = Some(ev.id + 1);
                        pos = e.frame_end();
                        adopted.push((ev, e));
                        None
                    }
                    Ok(ev) => Some(format!("frame id {} out of sequence", ev.id)),
                    Err(r) => Some(r),
                },
                Err(b) => Some(b.reason()),
            };
            if let Some(reason) = bad {
                let torn = jlen - pos;
                if torn > MAX_TORN {
                    return Err(corrupt(
                        &self.jp,
                        pos,
                        format!("{reason}, with {torn} bytes after it (more than one frame): not a torn tail; refusing"),
                    ));
                }
                if self.rec.table_rebuilt {
                    // The old table claimed committed events; never cut anything while
                    // rebuilding it.
                    return Err(corrupt(
                        &self.jp,
                        pos,
                        format!("{reason} while rebuilding journal.idx; refusing"),
                    ));
                }
                self.j.set_len(pos).map_err(io_err(&self.jp))?;
                self.j.sync_data().map_err(io_err(&self.jp))?;
                self.rec.torn_tail_at = Some(pos);
                self.rec.torn_bytes = torn;
                break;
            }
        }
        if !adopted.is_empty() {
            self.j.sync_data().map_err(io_err(&self.jp))?;
            for (ev, e) in &adopted {
                self.index_event(ev)?;
                if self.last == 0 {
                    self.base = ev.id;
                }
                self.write_entry(e)?;
                self.last = ev.id;
                self.end = e.frame_end();
                self.rec.adopted.push(ev.id);
            }
        }
        if self.rec.torn_tail_at.is_some() {
            self.clean_index_tails()?;
        }
        Ok(())
    }

    fn write_entry(&mut self, e: &Entry) -> Result<(), BoardError> {
        let off = (e.id - if self.last == 0 { e.id } else { self.base }) * ENTRY_BYTES;
        self.idx
            .write_all_at(&e.encode(), off)
            .map_err(io_err(&self.ip))?;
        self.idx.sync_data().map_err(io_err(&self.ip))
    }

    /// Append (and fsync) the topic and inbox index entries of one event.
    fn index_event(&self, ev: &Event) -> Result<(), BoardError> {
        let files = self.open_indexes(ev)?;
        for (p, f, _) in &files {
            append_id(p, f, ev.id)?;
        }
        let group: Vec<(&Path, &File)> = files.iter().map(|(p, f, _)| (p.as_path(), f)).collect();
        sync_group(&group)?;
        if files.iter().any(|(_, _, c)| *c) {
            fsync_dir(&self.board.root().join("topics"));
            fsync_dir(&self.board.root().join("inbox"));
        }
        Ok(())
    }

    fn open_indexes(&self, ev: &Event) -> Result<Vec<(PathBuf, File, bool)>, BoardError> {
        let root = self.board.root();
        let mut paths = vec![topic_file(root, &ev.topic)];
        for t in &ev.to {
            let p = inbox_file(root, t);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        paths
            .into_iter()
            .map(|p| open_rw(root, &p).map(|(f, c)| (p, f, c)))
            .collect()
    }

    /// After a torn tail was cut, drop index entries naming ids past the commit point (a
    /// crash between the index group and the table entry can leave them).
    fn clean_index_tails(&self) -> Result<(), BoardError> {
        let root = self.board.root();
        for d in ["topics", "inbox"] {
            let dir = root.join(d);
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for ent in rd.filter_map(|e| e.ok()) {
                let p = ent.path();
                if p.extension().and_then(|x| x.to_str()) != Some("idx") {
                    continue;
                }
                let (f, _) = open_rw(root, &p)?;
                let mut len = f.metadata().map_err(io_err(&p))?.len();
                len -= len % ID_BYTES;
                let before = len;
                while len >= ID_BYTES {
                    let mut b = [0u8; 8];
                    f.read_exact_at(&mut b, len - ID_BYTES)
                        .map_err(io_err(&p))?;
                    if u64::from_le_bytes(b) <= self.last {
                        break;
                    }
                    len -= ID_BYTES;
                }
                if len != before || f.metadata().map_err(io_err(&p))?.len() != len {
                    f.set_len(len).map_err(io_err(&p))?;
                    f.sync_data().map_err(io_err(&p))?;
                }
            }
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Snapshot, BoardError> {
        Snapshot::take(self.board)
    }
}

fn same_content(ev: &Event, p: &Post) -> bool {
    ev.thread == p.thread
        && ev.topic == p.topic
        && ev.to == p.to
        && ev.kind == p.kind
        && ev.parent == p.parent
        && ev.text == p.text
        && ev.refs == p.refs
}

impl Board {
    /// Append one event. Returns only after the fsync group (the ACK). With an idempotency
    /// key already used for the same body, returns that event's id (`dedup`); with a
    /// different body, refuses with [`BoardError::IdempotencyConflict`]. The body comparison
    /// covers thread, topic, to, kind, parent, text and refs, not the sender: two agents
    /// racing to post the same keyed message produce one event.
    pub fn post(&self, p: &Post) -> Result<PostReceipt, BoardError> {
        super::validate_post(p)?;
        let me = &Me {
            tag: p.from_tag.clone(),
            session: p.from.clone(),
        };
        let mut w = Writer::open(self)?;
        let binding = self.check_binding(me)?;
        self.touch_locked(me, &binding)?;
        if let Some(parent) = p.parent {
            if parent > w.last {
                return Err(BoardError::BadParent {
                    parent,
                    last: w.last,
                });
            }
        }
        if let Some(k) = &p.idem {
            let h = key_hash(H_IDEM, k.as_bytes());
            let snap = w.snapshot()?;
            let mut hit: Option<Result<u64, u64>> = None;
            snap.scan(snap.base, |e| {
                if e.idem_h == h {
                    let ev = snap.event(e)?;
                    if ev.idem.as_deref() == Some(k.as_str()) {
                        hit = Some(if same_content(&ev, p) {
                            Ok(ev.id)
                        } else {
                            Err(ev.id)
                        });
                        return Ok(false);
                    }
                }
                Ok(true)
            })?;
            match hit {
                Some(Ok(id)) => {
                    return Ok(PostReceipt {
                        id,
                        mission: self.id(),
                        dedup: true,
                        recovery: w.rec.clone(),
                        woke: 0,
                    })
                }
                Some(Err(existing)) => {
                    return Err(BoardError::IdempotencyConflict {
                        idem: k.clone(),
                        existing,
                    })
                }
                None => {}
            }
        }
        let lim = self.limits();
        let count = if w.last == 0 { 0 } else { w.last - w.base + 1 };
        if count >= lim.max_events {
            return Err(BoardError::BoardFull {
                what: "events",
                limit: lim.max_events,
            });
        }
        let ev = Event {
            id: w.last + 1,
            from_tag: me.tag.clone(),
            from: me.session.clone(),
            mission: self.id(),
            thread: p.thread.clone(),
            topic: p.topic.clone(),
            to: p.to.clone(),
            kind: p.kind,
            parent: p.parent,
            ts: self.now(),
            text: p.text.clone(),
            refs: p.refs.clone(),
            idem: p.idem.clone(),
        };
        let body = ev.body();
        if body.len() > MAX_FRAME_BYTES as usize {
            return Err(BoardError::TooLarge {
                field: "record",
                len: body.len(),
                limit: MAX_FRAME_BYTES as usize,
            });
        }
        let frame_bytes = frame::encode_frame(&body);
        if w.end + frame_bytes.len() as u64 > lim.max_journal_bytes {
            return Err(BoardError::BoardFull {
                what: "journal bytes",
                limit: lim.max_journal_bytes,
            });
        }
        // Open (and so vet) every index file before the journal is touched: a FIFO or link
        // planted under topics/ or inbox/ refuses the post with nothing written.
        let files = w.open_indexes(&ev)?;
        let entry = entry_for(&ev, w.end, body.len() as u32, frame::crc32c(&body));
        if fault_active("torn-journal-write") {
            let half = frame_bytes.len() / 2;
            let _ = w.j.write_all_at(&frame_bytes[..half], w.end);
            std::process::abort();
        }
        w.j.write_all_at(&frame_bytes, w.end)
            .map_err(io_err(&w.jp))?;
        fault("before-journal-fsync");
        w.j.sync_data().map_err(io_err(&w.jp))?;
        fault("after-journal-before-index");
        for (pth, f, _) in &files {
            append_id(pth, f, ev.id)?;
        }
        let group: Vec<(&Path, &File)> = files.iter().map(|(p, f, _)| (p.as_path(), f)).collect();
        sync_group(&group)?;
        if files.iter().any(|(_, _, c)| *c) {
            fsync_dir(&self.root().join("topics"));
            fsync_dir(&self.root().join("inbox"));
        }
        fault("before-table-entry");
        w.write_entry(&entry)?;
        fault("before-ack");
        let recovery = w.rec.clone();
        drop(w);
        let woke = if fault_active("drop-wake") {
            0
        } else {
            super::notify::wake_all(self.root(), ev.id)
        };
        Ok(PostReceipt {
            id: ev.id,
            mission: self.id(),
            dedup: false,
            recovery,
            woke,
        })
    }

    /// Run writer recovery now (what the next post would do first) and report it.
    pub fn recover(&self) -> Result<Recovery, BoardError> {
        Ok(Writer::open(self)?.rec)
    }

    /// Last committed id (0 when empty) and the oldest kept id (0 when empty).
    pub fn bounds(&self) -> Result<(u64, u64), BoardError> {
        let s = Snapshot::take(self)?;
        Ok((s.base, s.last))
    }

    /// Explicit compaction: keep events `keep_since..=last`. Refuses while a cursor still
    /// needs older events unless `expire_cursors`, which marks those cursors expired first
    /// (their owners get [`BoardError::CursorExpired`], never a silent gap).
    pub fn compact(
        &self,
        keep_since: u64,
        expire_cursors: bool,
    ) -> Result<CompactReport, BoardError> {
        let w = Writer::open(self)?;
        if w.last == 0 || keep_since <= w.base || keep_since > w.last {
            return Err(BoardError::BadKeepSince {
                keep_since,
                base: w.base,
                last: w.last,
            });
        }
        let lagging: Vec<String> = self
            .all_cursors()?
            .into_iter()
            .filter(|(_, c)| !c.expired && c.acked + 1 < keep_since)
            .map(|(t, _)| t)
            .collect();
        if !lagging.is_empty() && !expire_cursors {
            return Err(BoardError::CompactRefused {
                keep_since,
                tags: lagging,
            });
        }
        let snap = w.snapshot()?;
        let first = snap.entry(keep_since)?;
        let delta = first.offset;
        let bytes_before = w.end;
        let root = self.root();
        let jt = root.join(format!("{JOURNAL}.compact.tmp{}", std::process::id()));
        let it = root.join(format!("{TABLE}.compact.tmp{}", std::process::id()));
        {
            let mut nj = crate::record::create_temp(&jt)?;
            let mut buf = vec![0u8; 1 << 20];
            let mut off = delta;
            while off < w.end {
                let n = ((w.end - off) as usize).min(buf.len());
                w.j.read_exact_at(&mut buf[..n], off)
                    .map_err(io_err(&w.jp))?;
                nj.write_all(&buf[..n]).map_err(io_err(&jt))?;
                off += n as u64;
            }
            nj.sync_all().map_err(io_err(&jt))?;
            let mut ni = crate::record::create_temp(&it)?;
            let mut out = Vec::with_capacity(((w.last - keep_since + 1) * ENTRY_BYTES) as usize);
            snap.scan(keep_since, |e| {
                let mut e = *e;
                e.offset -= delta;
                out.extend_from_slice(&e.encode());
                Ok(true)
            })?;
            ni.write_all(&out).map_err(io_err(&it))?;
            ni.sync_all().map_err(io_err(&it))?;
        }
        let expired = if expire_cursors {
            self.expire_cursors(&lagging)?;
            lagging
        } else {
            Vec::new()
        };
        fs::rename(&jt, &w.jp).map_err(io_err(&w.jp))?;
        fault("compact-between-renames");
        fs::rename(&it, &w.ip).map_err(io_err(&w.ip))?;
        fsync_dir(root);
        self.trim_indexes(keep_since)?;
        Ok(CompactReport {
            base: keep_since,
            last: w.last,
            dropped_events: keep_since - w.base,
            bytes_before,
            bytes_after: w.end - delta,
            expired,
        })
    }

    /// Drop ids below `base` from every topic and inbox index (tmp + rename each; readers
    /// skip ids below the base anyway, so either version is correct).
    fn trim_indexes(&self, base: u64) -> Result<(), BoardError> {
        let root = self.root();
        for d in ["topics", "inbox"] {
            let dir = root.join(d);
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for ent in rd.filter_map(|e| e.ok()) {
                let p = ent.path();
                if p.extension().and_then(|x| x.to_str()) != Some("idx") {
                    continue;
                }
                let (ids, _) =
                    read_ids_after(&p, base - 1, u64::MAX, usize::MAX, self.limits().max_events)?;
                let mut data = Vec::with_capacity(ids.len() * 8);
                for id in ids {
                    data.extend_from_slice(&id.to_le_bytes());
                }
                let mut tmp = p.as_os_str().to_owned();
                tmp.push(format!(".tmp{}", std::process::id()));
                let tmp = PathBuf::from(tmp);
                let mut f = crate::record::create_temp(&tmp)?;
                f.write_all(&data).map_err(io_err(&tmp))?;
                f.sync_all().map_err(io_err(&tmp))?;
                fs::rename(&tmp, &p).map_err(io_err(&p))?;
            }
            fsync_dir(&dir);
        }
        Ok(())
    }

    /// Read-only verification that `journal.idx`, every topic index and every inbox index
    /// agree with `journal.log`. Takes the writer lock for a stable view, repairs nothing.
    pub fn check(&self) -> Result<CheckReport, BoardError> {
        let _lock = BoardLock::acquire(self.root())?;
        self.check_id_locked()?;
        let snap = Snapshot::take(self)?;
        let mut problems = Vec::new();
        let mut expect_topic: std::collections::BTreeMap<PathBuf, Vec<u64>> = Default::default();
        let mut expect_inbox: std::collections::BTreeMap<PathBuf, Vec<u64>> = Default::default();
        let jp = self.root().join(JOURNAL);
        let jlen = snap.jlen;
        let mut events = 0u64;
        let mut pos = 0u64;
        let mut committed_end = 0u64;
        if let Some(j) = &snap.journal {
            let mut want = snap.base;
            while pos < jlen {
                match read_frame(j, &jp, pos, jlen)? {
                    Ok((len, crc, body)) => {
                        let ev = match Event::from_body(&body) {
                            Ok(ev) => ev,
                            Err(r) => {
                                problems.push(format!("frame at {pos}: {r}"));
                                break;
                            }
                        };
                        if ev.mission != self.id() {
                            problems.push(format!(
                                "event {} at {pos} belongs to mission {}",
                                ev.id, ev.mission
                            ));
                        }
                        if ev.id > snap.last || snap.last == 0 {
                            problems.push(format!(
                                "event {} at {pos} is after the commit point (unacknowledged; the next post reconciles it)",
                                ev.id
                            ));
                            break;
                        }
                        if ev.id != want {
                            problems.push(format!("event {} at {pos}, expected {want}", ev.id));
                            break;
                        }
                        let e = entry_for(&ev, pos, len, crc);
                        match snap.entry(ev.id) {
                            Ok(t) if t == e => {}
                            Ok(t) => problems.push(format!(
                                "journal.idx entry {} is {t:?}, journal says {e:?}",
                                ev.id
                            )),
                            Err(err) => {
                                problems.push(format!("journal.idx entry {}: {err}", ev.id))
                            }
                        }
                        expect_topic
                            .entry(topic_file(self.root(), &ev.topic))
                            .or_default()
                            .push(ev.id);
                        let mut seen = Vec::new();
                        for t in &ev.to {
                            if !seen.contains(t) {
                                expect_inbox
                                    .entry(inbox_file(self.root(), t))
                                    .or_default()
                                    .push(ev.id);
                                seen.push(t.clone());
                            }
                        }
                        events += 1;
                        want += 1;
                        pos = e.frame_end();
                        committed_end = pos;
                    }
                    Err(b) => {
                        problems.push(format!(
                            "{} bytes after offset {pos} do not verify ({}): torn tail, cut by the next post",
                            jlen - pos,
                            b.reason()
                        ));
                        break;
                    }
                }
            }
        }
        if events
            != if snap.last == 0 {
                0
            } else {
                snap.last - snap.base + 1
            }
        {
            problems.push(format!(
                "journal holds {events} committed events, journal.idx names {}..={}",
                snap.base, snap.last
            ));
        }
        for (d, expect) in [("topics", &expect_topic), ("inbox", &expect_inbox)] {
            let dir = self.root().join(d);
            let mut found: Vec<PathBuf> = Vec::new();
            if let Ok(rd) = fs::read_dir(&dir) {
                for ent in rd.filter_map(|e| e.ok()) {
                    found.push(ent.path());
                }
            }
            found.sort();
            for p in &found {
                let want = expect.get(p).cloned().unwrap_or_default();
                match read_ids_after(
                    p,
                    snap.base.saturating_sub(1),
                    snap.last,
                    usize::MAX,
                    self.limits().max_events,
                ) {
                    Ok((ids, _)) if ids == want => {}
                    Ok((ids, _)) => problems.push(format!(
                        "{} lists {} ids, journal says {} ({:?} vs {:?})",
                        p.display(),
                        ids.len(),
                        want.len(),
                        &ids[..ids.len().min(8)],
                        &want[..want.len().min(8)]
                    )),
                    Err(e) => problems.push(format!("{}: {e}", p.display())),
                }
            }
            for (p, ids) in expect {
                if !found.contains(p) {
                    problems.push(format!(
                        "{} is missing ({} ids expected)",
                        p.display(),
                        ids.len()
                    ));
                }
            }
        }
        Ok(CheckReport {
            base: snap.base,
            last: snap.last,
            events,
            journal_bytes: jlen,
            committed_bytes: committed_end,
            problems,
        })
    }
}

/// Result of [`Board::compact`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactReport {
    pub base: u64,
    pub last: u64,
    pub dropped_events: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// Tags whose cursors were expired.
    pub expired: Vec<String>,
}

/// Result of [`Board::check`]: `problems` is empty when every index agrees with the journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    pub base: u64,
    pub last: u64,
    pub events: u64,
    pub journal_bytes: u64,
    pub committed_bytes: u64,
    pub problems: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}
