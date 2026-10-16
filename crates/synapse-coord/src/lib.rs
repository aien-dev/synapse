//! Shared agent coordination plane (claims, presence, whispers) compatible with the Crumb
//! RFC-0002 store, kept outside Synapse history.
//!
//! This crate is a Rust implementation of the RFC-0002 common coordination plane of
//! `tools/crumb/crumb.c` (aien-architecture 29780e5) that works on the **same store** the C
//! tool uses, so agents claiming through `crumb` in Git worktrees and agents claiming through
//! Synapse see one lock set. It never calls Git: the store root and the workspace are passed
//! in explicitly. See `README.md` for the design and the compatibility contract.
//!
//! Coordination state is ephemeral. It is never written into Synapse history, is never an
//! evidence receipt, and is never an authority for publication.

pub mod board;
pub mod identity;
pub mod json;
pub mod record;
pub mod time;

pub use identity::{
    resolve_coord_root, ResolvedRoot, RootSource, StoreId, STORE_ID_FILE, STORE_ID_FORMAT,
};
pub use record::{read_record_file, RecordRefusal, MAX_MARKER_BYTES, MAX_RECORD_BYTES};

use json::J;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// RFC-0001 schema version stamped into new directory records (`SCHEMA` in crumb.c).
pub const SCHEMA: &str = "1.0.0";
/// Rolling history entries kept per directory record (`HISTORY_CAP`).
pub const HISTORY_CAP: usize = 20;
/// Default presence (scent) lifetime in seconds (`SCENT_TTL`).
pub const SCENT_TTL: i64 = 3600;
/// Default claim (lock) lifetime in seconds (`LOCK_TTL`).
pub const LOCK_TTL: i64 = 1800;
/// Whispers older than this many seconds are pruned (`WHISPER_RETENTION`).
pub const WHISPER_RETENTION: i64 = 24 * 3600;

/// Everything that can go wrong. The C tool `die`s with exit 1 on all of these.
#[derive(Debug)]
pub enum CoordError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A record file exists but is not a JSON object. Like crumb.c, refuse rather than overwrite.
    CorruptRecord {
        path: PathBuf,
    },
    /// A store file is not a regular file, is a symlink, or is over its size cap (issue
    /// #58). Handled like [`CoordError::CorruptRecord`]: refused, never opened in a blocking
    /// way, never followed, never overwritten. See [`record`].
    RefusedRecord {
        path: PathBuf,
        reason: RecordRefusal,
    },
    /// A path normalizes to somewhere above the repository root.
    EscapesRoot {
        path: String,
    },
    /// An absolute target that is not inside this workspace.
    OutsideWorkspace {
        path: String,
        workspace: String,
    },
    BadPriority(String),
    BadAction(String),
    /// A relative target named from a subdirectory with no tree to resolve it against.
    AmbiguousWithoutTree {
        target: String,
        dir: String,
    },
    BadTtl(i64),
    /// Opened expecting a registered store identity, but the root has no `STORE_ID`
    /// marker: most likely a misconfigured root (a split coordination store).
    StoreIdMissing {
        root: PathBuf,
    },
    /// Opened expecting one store identity, but the root's marker names another store.
    StoreIdMismatch {
        root: PathBuf,
        expected: StoreId,
        found: StoreId,
    },
    /// `STORE_ID` exists but is not a v1 marker. Refused, never rewritten.
    StoreIdUnreadable {
        path: PathBuf,
        reason: String,
    },
    /// [`resolve_coord_root`] could not choose a root the way crumb.c would.
    RootUnresolved(String),
}

impl std::fmt::Display for CoordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            CoordError::CorruptRecord { path } => {
                write!(
                    f,
                    "{} is not valid JSON; fix or move it aside",
                    path.display()
                )
            }
            CoordError::RefusedRecord { path, reason } => write!(
                f,
                "{} {reason}; refusing to read it (fix or move it aside)",
                path.display()
            ),
            CoordError::EscapesRoot { path } => write!(f, "target {path} escapes the repository"),
            CoordError::OutsideWorkspace { path, workspace } => {
                write!(f, "target {path} is outside the repository {workspace}")
            }
            CoordError::AmbiguousWithoutTree { target, dir } => write!(
                f,
                "target {target} named from {dir} is ambiguous without a tree; name it from the root (dir .) or pass an absolute path"
            ),
            CoordError::BadPriority(p) => {
                write!(f, "priority must be low|normal|high|critical (got {p})")
            }
            CoordError::BadAction(a) => {
                write!(
                    f,
                    "action must be create|modify|delete|audit|test|build (got {a})"
                )
            }
            CoordError::BadTtl(t) => write!(f, "bad ttl: {t}"),
            CoordError::StoreIdMissing { root } => write!(
                f,
                "coordination store {} has no {STORE_ID_FILE} marker; refusing (expected a registered store: check CRUMB_COORD_ROOT / crumb.coordinationRoot / --store)",
                root.display()
            ),
            CoordError::StoreIdMismatch {
                root,
                expected,
                found,
            } => write!(
                f,
                "coordination store {} is store {found}, expected {expected}; refusing (split coordination roots)",
                root.display()
            ),
            CoordError::StoreIdUnreadable { path, reason } => {
                write!(f, "{} is not a store identity marker: {reason}", path.display())
            }
            CoordError::RootUnresolved(r) => write!(f, "cannot resolve coordination root: {r}"),
        }
    }
}

impl std::error::Error for CoordError {}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> CoordError + '_ {
    move |source| CoordError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `norm_path`: collapse `.`, `..` and repeated `/`. `None` when the path escapes the root.
/// A leading `/` is dropped, as in the C tool (`strtok` on `/`).
pub fn norm_path(s: &str) -> Option<String> {
    let mut st: Vec<&str> = Vec::new();
    for tok in s.split('/').filter(|t| !t.is_empty()) {
        match tok {
            "." => {}
            ".." => {
                st.pop()?;
            }
            t => st.push(t),
        }
    }
    if st.is_empty() {
        Some(".".to_string())
    } else {
        Some(st.join("/"))
    }
}

/// `key_dir`: the directory record a key belongs to (`.` for top-level keys).
pub fn key_dir(key: &str) -> String {
    match key.rfind('/') {
        Some(i) => key[..i].to_string(),
        None => ".".to_string(),
    }
}

/// `agent_path` file stem: every byte outside `[A-Za-z0-9._-]` becomes `_`.
pub fn agent_file_stem(agent: &str) -> String {
    agent
        .bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' {
                c as char
            } else {
                '_'
            }
        })
        .collect()
}

/// `session_id`: `CRUMB_SESSION` if set and non-empty, else `agent@host`. Never a PID alone.
pub fn default_session(agent: &str) -> String {
    if let Ok(s) = std::env::var("CRUMB_SESSION") {
        if !s.is_empty() {
            return s;
        }
    }
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for 256 bytes; gethostname writes at most len bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let host = if rc == 0 {
        buf[255] = 0;
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..n]).into_owned()
    } else {
        "unknown-host".to_string()
    };
    format!("{agent}@{host}")
}

/// Answers "does this repository-relative path exist?" for target-key resolution
/// (`exists_at` in crumb.c). A Git worktree answers from the filesystem; a Synapse
/// workspace answers from its snapshot.
pub trait PathOracle: Send + Sync {
    fn exists(&self, rel: &str) -> bool;
    /// False for an oracle that cannot see the tree. Relative targets named from a
    /// subdirectory are then refused: crumb.c would resolve them by file existence, so a
    /// blind guess could key one file twice and let two agents hold it.
    fn sees_tree(&self) -> bool {
        true
    }
}

/// Filesystem oracle (`lstat(top/rel)`), what crumb.c uses.
pub struct FsOracle(pub PathBuf);
impl PathOracle for FsOracle {
    fn exists(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.0.join(rel)).is_ok()
    }
}

/// Oracle that knows no files: keys then depend only on the strings given (see README).
pub struct NoOracle;
impl PathOracle for NoOracle {
    fn exists(&self, _rel: &str) -> bool {
        false
    }
    fn sees_tree(&self) -> bool {
        false
    }
}

/// Holder metadata written into lock and agent records. RFC-0002: branch, worktree path,
/// HEAD and base are holder metadata, never part of a resource's identity.
#[derive(Clone, Debug, Default)]
pub struct Holder {
    /// `branch` field. Git: short branch name or `(detached)`. Synapse: the lane/ref name.
    pub branch: String,
    /// `head` field. Git: 12-hex short commit. Synapse: first 12 hex of the ChangesetId.
    pub head: String,
    /// `base` field. Git: 12-hex merge-base with origin/main. Synapse: first 12 hex of the base ChangesetId.
    pub base: String,
    /// Extra `synapse_revision` field (full ChangesetId hex). Absent for Git holders.
    pub synapse_revision: Option<String>,
    /// Explicit session id; `None` means [`default_session`].
    pub session: Option<String>,
}

impl Holder {
    /// Metadata for an agent working in a Git worktree (what crumb.c records).
    pub fn git(branch: &str, head: &str, base: &str) -> Holder {
        Holder {
            branch: branch.to_string(),
            head: head.to_string(),
            base: base.to_string(),
            ..Holder::default()
        }
    }
    /// Metadata for an agent working in Synapse. `revision` and `base` are full ChangesetId
    /// hex strings; `head`/`base` get the same 12-character short form crumb.c uses so the
    /// C tool's displays stay readable, and the full id is kept in `synapse_revision`.
    pub fn synapse(lane: &str, revision: &str, base: &str) -> Holder {
        let short = |s: &str| s.chars().take(12).collect::<String>();
        Holder {
            branch: lane.to_string(),
            head: short(revision),
            base: short(base),
            synapse_revision: Some(revision.to_string()),
            session: None,
        }
    }
}

/// Where an agent is working: a workspace identity plus the files it can see.
pub struct Workspace {
    /// Absolute path label stored in `worktree` (crumb.c: `git rev-parse --show-toplevel`).
    /// For Synapse, the workspace directory the agent materialized, or any stable absolute
    /// label; absolute targets are accepted only under it.
    pub top: String,
    pub holder: Holder,
    pub oracle: Box<dyn PathOracle>,
}

impl Workspace {
    /// A Git worktree checkout at `top` (filesystem oracle).
    pub fn worktree(top: impl Into<String>, holder: Holder) -> Workspace {
        let top = top.into();
        Workspace {
            oracle: Box::new(FsOracle(PathBuf::from(&top))),
            top,
            holder,
        }
    }
    /// A workspace with a caller-supplied oracle (e.g. a Synapse snapshot).
    pub fn with_oracle(
        top: impl Into<String>,
        holder: Holder,
        oracle: Box<dyn PathOracle>,
    ) -> Workspace {
        Workspace {
            top: top.into(),
            holder,
            oracle,
        }
    }

    /// Repository-relative directory for a `dir` argument (relative or absolute under `top`).
    pub fn rel_dir(&self, dir: &str) -> Result<String, CoordError> {
        if dir.starts_with('/') {
            let t = self.top.trim_end_matches('/');
            if dir == t {
                return Ok(".".into());
            }
            let rest = dir
                .strip_prefix(t)
                .and_then(|r| r.strip_prefix('/'))
                .ok_or_else(|| CoordError::OutsideWorkspace {
                    path: dir.into(),
                    workspace: self.top.clone(),
                })?;
            return norm_path(rest).ok_or_else(|| CoordError::EscapesRoot { path: dir.into() });
        }
        norm_path(dir).ok_or_else(|| CoordError::EscapesRoot { path: dir.into() })
    }

    /// `target_key`: repository-relative key for a target named from directory `rel`.
    /// `<rel>/<target>` if that exists, else `<target>` from the root if that exists, else
    /// the repository-relative form when the target contains `/`, else `<rel>/<target>`.
    pub fn target_key(&self, target: &str, rel: &str) -> Result<String, CoordError> {
        if target.starts_with('/') {
            let t = self.top.trim_end_matches('/');
            let rest = target
                .strip_prefix(t)
                .and_then(|r| r.strip_prefix('/'))
                .ok_or_else(|| CoordError::OutsideWorkspace {
                    path: target.into(),
                    workspace: self.top.clone(),
                })?;
            return norm_path(rest).ok_or_else(|| CoordError::EscapesRoot {
                path: target.into(),
            });
        }
        if rel != "." && !self.oracle.sees_tree() {
            return Err(CoordError::AmbiguousWithoutTree {
                target: target.into(),
                dir: rel.into(),
            });
        }
        let joined = if rel != "." {
            format!("{rel}/{target}")
        } else {
            target.to_string()
        };
        let c1 = norm_path(&joined);
        let c2 = norm_path(target);
        if let Some(c) = c1.as_deref().filter(|c| *c != "." && self.oracle.exists(c)) {
            return Ok(c.to_string());
        }
        if let Some(c) = c2.as_deref().filter(|c| *c != "." && self.oracle.exists(c)) {
            return Ok(c.to_string());
        }
        if target.contains('/') {
            if let Some(c) = c2.clone() {
                return Ok(c);
            }
        }
        c1.or(c2).ok_or_else(|| CoordError::EscapesRoot {
            path: target.into(),
        })
    }
}

/// Close actions accepted by `crumb close`.
pub const ACTIONS: [&str; 6] = ["create", "modify", "delete", "audit", "test", "build"];
/// Whisper priorities accepted by `crumb whisper`.
pub const PRIORITIES: [&str; 4] = ["low", "normal", "high", "critical"];

/// A lock as stored under `locks` in a directory record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockView {
    pub key: String,
    pub holder: String,
    pub session: String,
    pub intent: String,
    pub worktree: String,
    pub branch: String,
    pub head: String,
    pub acquired_at: String,
    pub ttl_seconds: i64,
    pub synapse_revision: Option<String>,
    pub imported_from: Option<String>,
}

impl LockView {
    fn from(key: &str, e: &J) -> LockView {
        let s = |k: &str| e.str_of(k).unwrap_or_default();
        LockView {
            key: key.to_string(),
            holder: s("holder"),
            session: s("session"),
            intent: s("intent"),
            worktree: s("worktree"),
            branch: s("branch"),
            head: s("head"),
            acquired_at: s("acquired_at"),
            ttl_seconds: e.long_of("ttl_seconds", LOCK_TTL),
            synapse_revision: e.str_of("synapse_revision"),
            imported_from: e.str_of("imported_from"),
        }
    }
}

/// A live agent presence record (`agents/<agent>.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentView {
    pub agent: String,
    pub session: String,
    pub focus: String,
    pub dir: String,
    pub worktree: String,
    pub branch: String,
    pub head: String,
    pub updated_at: String,
    /// Seconds since `updated_at`, -1 when unparseable.
    pub heartbeat_age: i64,
    pub synapse_revision: Option<String>,
}

/// A whisper addressed to the sniffing agent or broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhisperView {
    pub from: String,
    pub to: Option<String>,
    pub message: String,
    pub timestamp: String,
    pub priority: Option<String>,
    pub target_file: Option<String>,
}

/// Result of a claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed {
        key: String,
    },
    /// Someone else holds an unexpired lock on the key (crumb.c exit code 2).
    Blocked {
        key: String,
        holder: Box<LockView>,
    },
}

/// Result of a close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseOutcome {
    Closed {
        key: String,
        lock_was_held: bool,
    },
    /// The key is held by another agent (crumb.c exit code 2).
    Refused {
        key: String,
        holder: String,
    },
}

/// Read-side view of the plane, the data behind `crumb sniff`.
#[derive(Clone, Debug, Default)]
pub struct Sniff {
    pub store: PathBuf,
    pub agents: Vec<AgentView>,
    pub locks: Vec<LockView>,
    /// Other workspaces seen in records: (worktree, agents there, conflicting keys under `dir`).
    pub other_workspaces: Vec<(String, Vec<String>, Vec<String>)>,
    pub whispers: Vec<WhisperView>,
    /// The store's identity marker; `None` until a mutating open has created it.
    pub store_id: Option<StoreId>,
}

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A coordination store at an explicit root (crumb.c: `<git-common-dir>/crumb/v1` or
/// `CRUMB_COORD_ROOT`). Layout: `dirs/<rel>.json` (`dirs/_root.json` for `.`),
/// `agents/<agent>.json`, `continuations/`, `ledger/`, and the transaction lock file `.lock`.
#[derive(Clone)]
pub struct CoordStore {
    root: PathBuf,
    clock: Clock,
    /// Registered identity this handle insists on (see [`CoordStore::open_expecting`]).
    expected: Option<StoreId>,
}

impl std::fmt::Debug for CoordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordStore")
            .field("root", &self.root)
            .field("expected", &self.expected)
            .finish()
    }
}

struct Rec {
    path: PathBuf,
    root: J,
    before: Vec<u8>,
    agent: bool,
    dead: bool,
}

/// POSIX record locks belong to the process, not the thread, and are dropped when the
/// process closes *any* descriptor for the file. One process-wide mutex therefore
/// serializes transactions inside this process; the `fcntl` lock serializes processes
/// (including crumb.c).
static IN_PROCESS: Mutex<()> = Mutex::new(());

struct Txn<'a> {
    store: &'a CoordStore,
    recs: Vec<Rec>,
    now: i64,
    lock: Option<(File, MutexGuard<'static, ()>)>,
}

impl CoordStore {
    /// Open a store without an identity expectation. The first mutating transaction (or
    /// [`CoordStore::ensure_store_id`]) creates the `STORE_ID` marker if it is absent.
    pub fn open(root: impl Into<PathBuf>) -> CoordStore {
        CoordStore {
            root: root.into(),
            clock: Arc::new(time::system_now),
            expected: None,
        }
    }

    /// Open a store that must carry the identity `expected` (the id Synapse registered for
    /// this repository). Refuses now, and again inside every later transaction, with
    /// [`CoordError::StoreIdMissing`] when the root has no marker and
    /// [`CoordError::StoreIdMismatch`] when it names another store. Such a handle never
    /// creates a marker, so a misconfigured root is never silently adopted.
    pub fn open_expecting(
        root: impl Into<PathBuf>,
        expected: StoreId,
    ) -> Result<CoordStore, CoordError> {
        let mut s = CoordStore::open(root);
        s.expected = Some(expected);
        s.check_expected()?;
        Ok(s)
    }

    /// The identity this handle insists on, if any.
    pub fn expected_store_id(&self) -> Option<StoreId> {
        self.expected
    }

    /// Read the store's identity marker without creating it (`None` if absent).
    pub fn store_id(&self) -> Result<Option<StoreId>, CoordError> {
        identity::read_marker(&self.root)
    }

    /// The store's identity, creating the marker under the store lock if absent (for an
    /// expecting handle: verified, never created). Use this to register a store.
    pub fn ensure_store_id(&self) -> Result<StoreId, CoordError> {
        let t = self.begin(true)?;
        let id = self.store_id()?.ok_or_else(|| CoordError::StoreIdMissing {
            root: self.root.clone(),
        })?;
        t.commit()?;
        Ok(id)
    }

    fn check_expected(&self) -> Result<(), CoordError> {
        let Some(expected) = self.expected else {
            return Ok(());
        };
        match identity::read_marker(&self.root)? {
            None => Err(CoordError::StoreIdMissing {
                root: self.root.clone(),
            }),
            Some(found) if found != expected => Err(CoordError::StoreIdMismatch {
                root: self.root.clone(),
                expected,
                found,
            }),
            Some(_) => Ok(()),
        }
    }

    /// Replace the clock (Unix seconds). For tests of expiry.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> CoordStore {
        self.clock = Arc::new(clock);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir_path(&self, rel: &str) -> PathBuf {
        if rel == "." {
            self.root.join("dirs/_root.json")
        } else {
            self.root.join("dirs").join(format!("{rel}.json"))
        }
    }

    fn agent_path(&self, agent: &str) -> PathBuf {
        self.root
            .join("agents")
            .join(format!("{}.json", agent_file_stem(agent)))
    }

    fn begin(&self, mutate: bool) -> Result<Txn<'_>, CoordError> {
        let mut t = Txn {
            store: self,
            recs: Vec::new(),
            now: (self.clock)(),
            lock: None,
        };
        // An expecting handle refuses a wrong root before creating anything in it.
        self.check_expected()?;
        if !mutate {
            return Ok(t);
        }
        for sub in ["dirs", "agents", "continuations", "ledger"] {
            let d = self.root.join(sub);
            fs::create_dir_all(&d).map_err(io_err(&d))?;
        }
        let guard = IN_PROCESS.lock().unwrap_or_else(|e| e.into_inner());
        let lp = self.root.join(".lock");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&lp)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => CoordError::RefusedRecord {
                    path: lp.clone(),
                    reason: RecordRefusal::Symlink,
                },
                // A directory planted as `.lock` is a refused store file, not an I/O error.
                Some(libc::EISDIR) => CoordError::RefusedRecord {
                    path: lp.clone(),
                    reason: RecordRefusal::NotRegular("directory"),
                },
                _ => io_err(&lp)(e),
            })?;
        // The lock file is a store file too: a FIFO or device planted as `.lock` is refused.
        let m = f.metadata().map_err(io_err(&lp))?;
        if let Some(reason) = record::refusal_for(&m.file_type()) {
            return Err(CoordError::RefusedRecord { path: lp, reason });
        }
        // SAFETY: zeroed flock is a valid "whole file from offset 0" request.
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
                return Err(CoordError::Io {
                    path: lp,
                    source: e,
                });
            }
        }
        t.lock = Some((f, guard));
        // Under the lock: re-check the expectation (the marker could have changed since),
        // or create the marker on this store's first mutating open.
        if self.expected.is_some() {
            self.check_expected()?;
        } else {
            identity::ensure_marker_locked(&self.root)?;
        }
        Ok(t)
    }
}

/// `sweep` (RFC-0001 SPEC 5.4): drop expired scents and locks, and whispers past retention.
fn sweep(root: &mut J, now: i64) {
    if let Some(J::Obj(sc)) = root.get_mut("active_scents") {
        sc.retain(|(_, v)| {
            let u = time::parse_iso(v.bytes_of("updated_at"));
            !(u < 0 || now - u > v.long_of("ttl_seconds", SCENT_TTL))
        });
    }
    if let Some(J::Obj(lk)) = root.get_mut("locks") {
        lk.retain(|(_, v)| {
            let u = time::parse_iso(v.bytes_of("acquired_at"));
            !(u < 0 || now - u > v.long_of("ttl_seconds", LOCK_TTL))
        });
    }
    if let Some(J::Arr(wh)) = root.get_mut("whispers") {
        wh.retain(|v| {
            let u = time::parse_iso(v.bytes_of("timestamp"));
            !(u >= 0 && now - u > WHISPER_RETENTION)
        });
    }
}

fn has_lock_by(root: &J, agent: &str) -> bool {
    match root.get("locks") {
        Some(J::Obj(m)) => m
            .iter()
            .any(|(_, v)| v.str_of("holder").as_deref() == Some(agent)),
        _ => false,
    }
}

/// Best-effort directory flush. Opened like every other store file: never following a final
/// link, never blocking (a FIFO planted in place of a directory cannot stall the writer),
/// and only if it really is a directory.
fn fsync_dir(dir: &Path) {
    if let Ok(f) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir)
    {
        let _ = f.sync_all();
    }
}

/// `durable_write`: write `<path>.tmp<pid>`, fsync, rename over `path`, fsync the directory.
/// A crash before the rename leaves the old record intact and a `*.tmp<pid>` file that no
/// reader ever loads (only names ending in `.json` are records).
///
/// Refuses (typed [`CoordError::RefusedRecord`]) to replace anything but a regular file, and
/// to write a record over [`MAX_RECORD_BYTES`], which readers would refuse.
fn durable_write(root: &Path, path: &Path, data: &[u8]) -> Result<(), CoordError> {
    if data.len() as u64 > MAX_RECORD_BYTES {
        return Err(CoordError::RefusedRecord {
            path: path.to_path_buf(),
            reason: RecordRefusal::TooLarge {
                limit: MAX_RECORD_BYTES,
            },
        });
    }
    record::check_real_parents(root, path)?;
    record::check_replaceable(path)?;
    let dd = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dd).map_err(io_err(dd))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    {
        let mut f = record::create_temp(&tmp)?;
        f.write_all(data).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
    }
    fault_point("before-rename");
    fs::rename(&tmp, path).map_err(io_err(path))?;
    fsync_dir(dd);
    Ok(())
}

/// Test-only fault injection: `SYNAPSE_COORD_FAULT=<point>` aborts the process at that point
/// (used by the crash-mid-write test through the CLI binary). Unset in normal use.
fn fault_point(point: &str) {
    if std::env::var("SYNAPSE_COORD_FAULT").as_deref() == Ok(point) {
        std::process::abort();
    }
}

/// List record names under `dir`, recursively, without opening any entry. Entry types come
/// from the directory entry (`d_type`, falling back to `lstat`), so nothing is followed:
/// real subdirectories are walked, symlinked directories are not (crumb.c follows them with
/// `stat`; not following also rules out a symlink loop). Every name ending in `.json` that
/// is not a directory is returned, whatever its type; [`record::read_bounded`] then refuses
/// a non-regular one without opening it, so a planted FIFO is reported, never read.
fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut ents: Vec<_> = rd
        .filter_map(|e| e.ok())
        .map(|e| (e.path(), e.file_type().ok()))
        .collect();
    ents.sort_by(|a, b| a.0.cmp(&b.0));
    for (full, ft) in ents {
        if ft.is_some_and(|t| t.is_dir()) {
            collect_json(&full, out);
        } else if let Some(n) = full.file_name().and_then(|n| n.to_str()) {
            if n.len() > 5 && n.ends_with(".json") {
                out.push(full);
            }
        }
    }
}

impl Txn<'_> {
    /// `rec_load`: load (once) and prepare a record. `label` is the directory for dir records.
    fn load(&mut self, path: &Path, agent: bool, label: Option<&str>) -> Result<usize, CoordError> {
        if let Some(i) = self.recs.iter().position(|r| r.path == path) {
            return Ok(i);
        }
        // Never read through a symlinked directory: listing does not follow one, so a record
        // behind it would be invisible to prune yet loadable and writable here.
        record::check_real_parents(&self.store.root, path)?;
        let (mut j, existed) = match record::read_bounded(path, MAX_RECORD_BYTES)? {
            Some(bytes) => match json::parse(&bytes) {
                Some(j) if j.is_obj() => (j, true),
                _ => {
                    return Err(CoordError::CorruptRecord {
                        path: path.to_path_buf(),
                    })
                }
            },
            None => (J::obj(), false),
        };
        if !agent {
            if j.get("schema_version").is_none() {
                j.set("schema_version", J::str(SCHEMA));
            }
            if j.get("directory").is_none() {
                j.set("directory", J::str(label.unwrap_or(".")));
            }
        }
        let before = j.dump();
        let mut dead = false;
        if agent {
            let u = time::parse_iso(j.bytes_of("updated_at"));
            if existed && (u < 0 || self.now - u > j.long_of("ttl_seconds", SCENT_TTL)) {
                dead = true;
            }
        } else {
            sweep(&mut j, self.now);
        }
        self.recs.push(Rec {
            path: path.to_path_buf(),
            root: j,
            before,
            agent,
            dead,
        });
        Ok(self.recs.len() - 1)
    }

    fn dir_rec(&mut self, rel: &str) -> Result<usize, CoordError> {
        let p = self.store.dir_path(rel);
        self.load(&p, false, Some(rel))
    }

    fn agent_rec(&mut self, agent: &str) -> Result<usize, CoordError> {
        let p = self.store.agent_path(agent);
        self.load(&p, true, None)
    }

    /// `txn_prune`: load every record so expired entries drop out (written back on commit).
    fn prune(&mut self) -> Result<(), CoordError> {
        let dd = self.store.root.join("dirs");
        let mut f = Vec::new();
        collect_json(&dd, &mut f);
        for p in f {
            let rel = p
                .strip_prefix(&dd)
                .ok()
                .and_then(|r| r.to_str())
                .map(|r| r[..r.len() - 5].to_string())
                .unwrap_or_default();
            let label = if rel == "_root" { "." } else { rel.as_str() };
            self.load(&p, false, Some(label))?;
        }
        let mut g = Vec::new();
        collect_json(&self.store.root.join("agents"), &mut g);
        for p in g {
            self.load(&p, true, None)?;
        }
        Ok(())
    }

    /// `txn_end(commit = 1)`: unlink dead agent records, durably write changed records,
    /// then release the OS lock.
    fn commit(mut self) -> Result<(), CoordError> {
        for r in &self.recs {
            if r.dead {
                if fs::remove_file(&r.path).is_ok() {
                    fsync_dir(r.path.parent().unwrap_or(Path::new(".")));
                }
                continue;
            }
            let now = r.root.dump();
            if now != r.before {
                durable_write(&self.store.root, &r.path, &now)?;
            }
        }
        self.lock.take();
        Ok(())
    }

    fn agent_set(
        &mut self,
        ws: &Workspace,
        agent: &str,
        focus: &str,
        rel: &str,
        ttl: i64,
    ) -> Result<(), CoordError> {
        let i = self.agent_rec(agent)?;
        let mut e = J::obj();
        e.set("agent", J::str(agent));
        e.set("session", J::str(&session_of(ws, agent)));
        e.set("focus", J::str(focus));
        e.set("dir", J::str(rel));
        holder_fields(&mut e, ws);
        e.set("updated_at", J::str(&time::iso(self.now)));
        e.set("ttl_seconds", J::num(ttl));
        if let Some(r) = &ws.holder.synapse_revision {
            e.set("synapse_revision", J::str(r));
        }
        let r = &mut self.recs[i];
        r.dead = false;
        r.root = e;
        Ok(())
    }

    fn agent_has_lock(&self, agent: &str) -> bool {
        self.recs
            .iter()
            .any(|r| !r.agent && has_lock_by(&r.root, agent))
    }
}

fn session_of(ws: &Workspace, agent: &str) -> String {
    ws.holder
        .session
        .clone()
        .unwrap_or_else(|| default_session(agent))
}

fn holder_fields(e: &mut J, ws: &Workspace) {
    e.set("worktree", J::str(&ws.top));
    e.set("branch", J::str(&ws.holder.branch));
    e.set("head", J::str(&ws.holder.head));
    e.set("base", J::str(&ws.holder.base));
}

fn whisper_add(
    root: &mut J,
    now: i64,
    from: &str,
    to: Option<&str>,
    msg: &str,
    prio: Option<&str>,
    tf: Option<&str>,
) {
    let mut e = J::obj();
    e.set("from", J::str(from));
    if let Some(to) = to.filter(|t| *t != "-") {
        e.set("to", J::str(to));
    }
    e.set("message", J::str(msg));
    if let Some(tf) = tf.filter(|t| !t.is_empty()) {
        e.set("target_file", J::str(tf));
    }
    e.set("timestamp", J::str(&time::iso(now)));
    if let Some(p) = prio.filter(|p| !p.is_empty()) {
        e.set("priority", J::str(p));
    }
    root.arr_of("whispers").push(e);
}

fn history_add(root: &mut J, now: i64, agent: &str, action: &str, target: &str, intent: &str) {
    let mut e = J::obj();
    e.set("agent", J::str(agent));
    e.set("action", J::str(action));
    e.set("target", J::str(target));
    e.set("intent", J::str(intent));
    e.set("vector", J::str(""));
    e.set("timestamp", J::str(&time::iso(now)));
    let h = root.arr_of("history");
    h.push(e);
    if h.len() > HISTORY_CAP {
        let d = h.len() - HISTORY_CAP;
        h.drain(..d);
    }
}

impl CoordStore {
    /// `crumb claim`: take the advisory lock on `target` (named from directory `dir`).
    /// `ttl` defaults to [`LOCK_TTL`]. Re-claiming one's own lock refreshes it.
    pub fn claim(
        &self,
        ws: &Workspace,
        agent: &str,
        dir: &str,
        target: &str,
        intent: &str,
        ttl: Option<i64>,
    ) -> Result<ClaimOutcome, CoordError> {
        let ttl = check_ttl(ttl, LOCK_TTL)?;
        let rel = ws.rel_dir(dir)?;
        let key = ws.target_key(target, &rel)?;
        let td = key_dir(&key);
        let mut t = self.begin(true)?;
        t.prune()?;
        let ti = t.dir_rec(&td)?;
        let now = t.now;
        let locks = t.recs[ti].root.obj_of("locks");
        if let Some(cur) = locks.get(&key) {
            if let Some(h) = cur.str_of("holder") {
                if h != agent {
                    let holder = LockView::from(&key, cur);
                    t.commit()?;
                    return Ok(ClaimOutcome::Blocked {
                        key,
                        holder: Box::new(holder),
                    });
                }
            }
        }
        let mut e = J::obj();
        e.set("holder", J::str(agent));
        e.set("session", J::str(&session_of(ws, agent)));
        e.set("target", J::str(&key));
        e.set("intent", J::str(intent));
        holder_fields(&mut e, ws);
        e.set("acquired_at", J::str(&time::iso(now)));
        e.set("ttl_seconds", J::num(ttl));
        if let Some(r) = &ws.holder.synapse_revision {
            e.set("synapse_revision", J::str(r));
        }
        locks.set(&key, e);
        t.agent_set(ws, agent, intent, &rel, SCENT_TTL.max(ttl))?;
        t.commit()?;
        Ok(ClaimOutcome::Claimed { key })
    }

    /// `crumb update`: refresh this agent's presence. `ttl` defaults to [`SCENT_TTL`].
    pub fn update(
        &self,
        ws: &Workspace,
        agent: &str,
        dir: &str,
        focus: &str,
        ttl: Option<i64>,
    ) -> Result<(), CoordError> {
        let ttl = check_ttl(ttl, SCENT_TTL)?;
        let rel = ws.rel_dir(dir)?;
        let mut t = self.begin(true)?;
        t.prune()?;
        t.agent_set(ws, agent, focus, &rel, ttl)?;
        t.commit()
    }

    /// `crumb whisper`: leave a message in the record of directory `dir`. `to = None` or
    /// `Some("-")` broadcasts.
    #[allow(clippy::too_many_arguments)]
    pub fn whisper(
        &self,
        ws: &Workspace,
        from: &str,
        dir: &str,
        to: Option<&str>,
        msg: &str,
        priority: Option<&str>,
        target_file: Option<&str>,
    ) -> Result<(), CoordError> {
        if let Some(p) = priority.filter(|p| !p.is_empty()) {
            if !PRIORITIES.contains(&p) {
                return Err(CoordError::BadPriority(p.into()));
            }
        }
        let rel = ws.rel_dir(dir)?;
        let mut t = self.begin(true)?;
        t.prune()?;
        let i = t.dir_rec(&rel)?;
        let now = t.now;
        whisper_add(
            &mut t.recs[i].root,
            now,
            from,
            to,
            msg,
            priority,
            target_file,
        );
        t.commit()
    }

    /// `crumb close`: release the lock, append a history vector, optionally whisper.
    /// The agent's presence record is removed when it holds no other lock.
    pub fn close(
        &self,
        ws: &Workspace,
        agent: &str,
        dir: &str,
        target: &str,
        action: &str,
        msg: Option<&str>,
    ) -> Result<CloseOutcome, CoordError> {
        if !ACTIONS.contains(&action) {
            return Err(CoordError::BadAction(action.into()));
        }
        let rel = ws.rel_dir(dir)?;
        let key = ws.target_key(target, &rel)?;
        let td = key_dir(&key);
        let mut t = self.begin(true)?;
        t.prune()?;
        let ti = t.dir_rec(&td)?;
        let now = t.now;
        let root = &mut t.recs[ti].root;
        let cur = root.obj_of("locks").get(&key).cloned();
        let mut intent = String::new();
        if let Some(cur) = &cur {
            if let Some(h) = cur.str_of("holder") {
                if h != agent {
                    t.commit()?;
                    return Ok(CloseOutcome::Refused { key, holder: h });
                }
            }
            if let Some(i) = cur.str_of("intent") {
                intent = i;
            }
        }
        history_add(root, now, agent, action, &key, &intent);
        if cur.is_some() {
            root.obj_of("locks").del(&key);
        }
        if !t.agent_has_lock(agent) {
            let ai = t.agent_rec(agent)?;
            t.recs[ai].dead = true;
        }
        if let Some(m) = msg.filter(|m| !m.is_empty()) {
            whisper_add(
                &mut t.recs[ti].root,
                now,
                agent,
                None,
                m,
                Some("normal"),
                Some(&key),
            );
        }
        t.commit()?;
        Ok(CloseOutcome::Closed {
            key,
            lock_was_held: cur.is_some(),
        })
    }

    /// `crumb sniff` (shared-plane part): live agents, live locks, other workspaces with
    /// conflicts under `dir`, and whispers in `dir` addressed to `agent` or broadcast.
    /// Read-only: takes no lock and writes nothing (expired entries are hidden in memory).
    pub fn sniff(&self, ws: &Workspace, agent: &str, dir: &str) -> Result<Sniff, CoordError> {
        let rel = ws.rel_dir(dir)?;
        let mut t = self.begin(false)?;
        t.prune()?;
        let now = t.now;
        let mut s = Sniff {
            store: self.root.clone(),
            store_id: self.store_id()?,
            ..Sniff::default()
        };
        for r in t
            .recs
            .iter()
            .filter(|r| r.agent && !r.dead && r.root.get("updated_at").is_some())
        {
            let e = &r.root;
            let st = |k: &str| e.str_of(k).unwrap_or_default();
            let u = time::parse_iso(e.bytes_of("updated_at"));
            s.agents.push(AgentView {
                agent: st("agent"),
                session: st("session"),
                focus: st("focus"),
                dir: st("dir"),
                worktree: st("worktree"),
                branch: st("branch"),
                head: st("head"),
                updated_at: st("updated_at"),
                heartbeat_age: if u < 0 { -1 } else { now - u },
                synapse_revision: e.str_of("synapse_revision"),
            });
        }
        for r in t.recs.iter().filter(|r| !r.agent) {
            if let Some(J::Obj(m)) = r.root.get("locks") {
                for (k, v) in m {
                    s.locks.push(LockView::from(&String::from_utf8_lossy(k), v));
                }
            }
        }
        let mut others: Vec<String> = s
            .agents
            .iter()
            .map(|a| a.worktree.clone())
            .chain(s.locks.iter().map(|l| l.worktree.clone()))
            .filter(|w| !w.is_empty() && *w != ws.top)
            .collect();
        others.sort();
        others.dedup();
        for w in others {
            let agents = s
                .agents
                .iter()
                .filter(|a| a.worktree == w)
                .map(|a| a.agent.clone())
                .collect();
            let conflicts = s
                .locks
                .iter()
                .filter(|l| l.worktree == w)
                .filter(|l| rel == "." || l.key.starts_with(&format!("{rel}/")))
                .map(|l| l.key.clone())
                .collect();
            s.other_workspaces.push((w, agents, conflicts));
        }
        let di = t.dir_rec(&rel)?;
        if let Some(J::Arr(wh)) = t.recs[di].root.get("whispers") {
            for w in wh {
                let to = w.str_of("to");
                if to.as_deref().is_some_and(|to| to != agent) {
                    continue;
                }
                s.whispers.push(WhisperView {
                    from: w.str_of("from").unwrap_or_else(|| "?".into()),
                    to,
                    message: w.str_of("message").unwrap_or_default(),
                    timestamp: w.str_of("timestamp").unwrap_or_default(),
                    priority: w.str_of("priority"),
                    target_file: w.str_of("target_file"),
                });
            }
        }
        Ok(s)
    }
}

fn check_ttl(ttl: Option<i64>, dflt: i64) -> Result<i64, CoordError> {
    match ttl {
        None => Ok(dflt),
        Some(t) if t < 0 => Err(CoordError::BadTtl(t)),
        Some(t) => Ok(t),
    }
}

impl Sniff {
    /// Text rendering in the shape of crumb.c's sniff sections (for humans and scripts).
    pub fn render(&self, ws: &Workspace, agent: &str) -> String {
        use std::fmt::Write as _;
        let mut o = String::new();
        let _ = writeln!(o, "shared coordination: ACTIVE");
        let _ = writeln!(o, "  common root: {}", self.store.display());
        match &self.store_id {
            Some(id) => writeln!(o, "  store id: {id}"),
            None => writeln!(o, "  store id: (none yet)"),
        }
        .ok();
        let _ = writeln!(
            o,
            "  this workspace: {} [{} {}] as {agent}",
            ws.top, ws.holder.branch, ws.holder.head
        );
        let _ = writeln!(o, "ACTIVE AGENTS");
        if self.agents.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for a in &self.agents {
            let _ = writeln!(
                o,
                "  agent   {:<16} branch {}  focus: {}  heartbeat {}s ago  [{}]",
                a.agent, a.branch, a.focus, a.heartbeat_age, a.worktree
            );
        }
        let _ = writeln!(o, "LOCKS");
        if self.locks.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for l in &self.locks {
            let imp = l
                .imported_from
                .as_deref()
                .map(|f| format!(" imported from {f}"))
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "  lock    {:<16} held by {} [{}]: {}  [{}]{imp}",
                l.key, l.holder, l.branch, l.intent, l.acquired_at
            );
        }
        let _ = writeln!(o, "OTHER WORKSPACES");
        if self.other_workspaces.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for (w, agents, conflicts) in &self.other_workspaces {
            let a = if agents.is_empty() {
                "no agents".to_string()
            } else {
                format!("agent {}", agents.join(", "))
            };
            let c = if conflicts.is_empty() {
                "; conflicts: none".to_string()
            } else {
                format!("; CONFLICT: {}", conflicts.join(", "))
            };
            let _ = writeln!(o, "  {w}: {a}{c}");
        }
        let _ = writeln!(o, "WHISPERS");
        if self.whispers.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for w in &self.whispers {
            let p = w
                .priority
                .as_deref()
                .map(|p| format!(" {p}"))
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "  whisper {} -> {}: {}  [{}{p}]",
                w.from,
                w.to.as_deref().unwrap_or("all"),
                w.message,
                w.timestamp
            );
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_path_rules() {
        assert_eq!(norm_path("a/./b//c").as_deref(), Some("a/b/c"));
        assert_eq!(norm_path("src/../src/./x.c").as_deref(), Some("src/x.c"));
        assert_eq!(norm_path("./").as_deref(), Some("."));
        assert_eq!(norm_path("/abs/x").as_deref(), Some("abs/x"));
        assert_eq!(norm_path("../x"), None);
        assert_eq!(norm_path("a/../../x"), None);
    }

    #[test]
    fn key_dir_and_agent_stem() {
        assert_eq!(key_dir("src/a.c"), "src");
        assert_eq!(key_dir("a.c"), ".");
        assert_eq!(agent_file_stem("lane A/b@c"), "lane_A_b_c");
    }
}
