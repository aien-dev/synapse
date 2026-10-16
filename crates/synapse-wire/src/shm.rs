//! The operating-system calls the shared-memory ring needs (Linux, 64-bit): a sealed
//! `memfd` region mapped `MAP_SHARED`, and a futex doorbell. This is the only unsafe code in
//! the crate outside the fuzzer's counting allocator.
//!
//! Declarations and constants are taken from the system headers on the build host (glibc
//! 2.39, aarch64): `sys/mman.h` (`mmap`, `munmap`, `MAP_FAILED`), `bits/mman-linux.h`
//! (`PROT_READ` 1, `PROT_WRITE` 2, `MAP_SHARED` 1), `bits/mman-shared.h` (`memfd_create`),
//! `linux/memfd.h` (`MFD_CLOEXEC` 1, `MFD_ALLOW_SEALING` 2), `bits/fcntl-linux.h`
//! (`F_ADD_SEALS` 1033, `F_GET_SEALS` 1034, `F_SEAL_SEAL` 1, `F_SEAL_SHRINK` 2,
//! `F_SEAL_GROW` 4), `linux/futex.h` (`FUTEX_WAIT` 0, `FUTEX_WAKE` 1) and
//! `asm-generic/unistd.h` (`__NR_futex` 98 on aarch64); 202 on x86_64 as in the kernel's
//! `syscall_64.tbl` (cross-checked against the `libc` 0.2.189 crate source in the local
//! registry). On 64-bit Linux `off_t` and `long` are 64 bits.
//!
//! Why sealed: a reader of a file-backed mapping takes `SIGBUS` if the peer shrinks the file
//! under it. The creator seals its `memfd` against shrinking and growing before anyone can
//! attach, and an attacher refuses any file without the shrink seal.

use crate::ring::RingRefusal;
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_SHARED: c_int = 0x01;
const MFD_CLOEXEC: c_uint = 0x0001;
const MFD_ALLOW_SEALING: c_uint = 0x0002;
const F_ADD_SEALS: c_int = 1033;
const F_GET_SEALS: c_int = 1034;
const F_SEAL_SEAL: c_int = 0x0001;
const F_SEAL_SHRINK: c_int = 0x0002;
const F_SEAL_GROW: c_int = 0x0004;

extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn memfd_create(name: *const std::ffi::c_char, flags: c_uint) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

/// A `MAP_SHARED` mapping of a whole sealed file, viewed as `u64` atomics.
pub(crate) struct Mapping {
    ptr: NonNull<AtomicU64>,
    len: usize,
    file: File,
}

// SAFETY: the mapping is plain shared memory that stays mapped until `drop`, and it is only
// ever accessed through `AtomicU64` (see `words`), so sharing or sending the handle between
// threads cannot create a data race.
unsafe impl Send for Mapping {}
// SAFETY: as for `Send`: every access through `&Mapping` is an atomic operation.
unsafe impl Sync for Mapping {}

pub(crate) enum AttachError {
    Io(std::io::Error),
    Refused(RingRefusal),
}

impl Mapping {
    /// A new anonymous memory file of `len` bytes (zero-filled), sealed against shrinking,
    /// growing and further sealing, then mapped.
    pub(crate) fn create(len: usize) -> std::io::Result<Self> {
        // SAFETY: the name is a NUL-terminated literal; memfd_create reads it and returns a
        // new descriptor or -1.
        let fd = unsafe { memfd_create(c"synapse-ring".as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by memfd_create, is open, and nothing else owns it.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        file.set_len(len as u64)?;
        // SAFETY: F_ADD_SEALS takes one int argument; `file` keeps the descriptor open.
        let rc = unsafe {
            fcntl(
                file.as_raw_fd(),
                F_ADD_SEALS,
                F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Self::map(file, len)
    }

    /// Open and map a region another process created. Refused unless the file carries the
    /// shrink seal and is exactly `len` bytes long.
    pub(crate) fn attach(path: &Path, len: usize) -> Result<Self, AttachError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(AttachError::Io)?;
        // SAFETY: F_GET_SEALS takes no further argument; `file` keeps the descriptor open.
        let seals = unsafe { fcntl(file.as_raw_fd(), F_GET_SEALS) };
        if seals < 0 || seals & F_SEAL_SHRINK == 0 {
            return Err(AttachError::Refused(RingRefusal::RegionNotSealed));
        }
        let found = file.metadata().map_err(AttachError::Io)?.len();
        if found != len as u64 {
            return Err(AttachError::Refused(RingRefusal::RegionSize {
                need: len,
                found: found as usize,
            }));
        }
        Self::map(file, len).map_err(AttachError::Io)
    }

    fn map(file: File, len: usize) -> std::io::Result<Self> {
        // SAFETY: a fresh mapping (null hint) of `len` bytes of an open file whose size is
        // `len` and cannot shrink (sealed); the kernel validates every argument.
        let p = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        // MAP_FAILED is ((void *) -1).
        if p as usize == usize::MAX {
            return Err(std::io::Error::last_os_error());
        }
        let ptr = NonNull::new(p.cast::<AtomicU64>())
            .ok_or_else(|| std::io::Error::other("mmap returned null"))?;
        Ok(Self { ptr, len, file })
    }

    /// The mapping as words. Every access is atomic, so a peer process writing the same
    /// memory concurrently is not a data race on this side.
    pub(crate) fn words(&self) -> &[AtomicU64] {
        // SAFETY: `ptr` is the start of a live mapping of `len` bytes (unmapped only in
        // `drop`, which needs `&mut self`); mappings are page aligned, so the pointer is
        // aligned for `AtomicU64`; `AtomicU64` has the size and layout of `u64` and every bit
        // pattern is valid; the file cannot shrink, so every page stays backed.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len / 8) }
    }

    pub(crate) fn attach_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the mapping made in `map`; no reference from `words` can
        // outlive `&self`, and `drop` has exclusive access.
        unsafe {
            munmap(self.ptr.as_ptr().cast::<c_void>(), self.len);
        }
    }
}

#[cfg(target_arch = "aarch64")]
const SYS_FUTEX: c_long = 98;
#[cfg(target_arch = "x86_64")]
const SYS_FUTEX: c_long = 202;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const FUTEX_WAIT: c_int = 0;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const FUTEX_WAKE: c_int = 1;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// The futex word: the low 32 bits of the doorbell word.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn futex_word(word: &AtomicU64) -> *const u32 {
    let p = word.as_ptr().cast::<u32>().cast_const();
    if cfg!(target_endian = "big") {
        p.wrapping_add(1)
    } else {
        p
    }
}

/// Sleep until the doorbell's low 32 bits differ from `expected`, a wake, or `timeout`.
/// Shared (not private) futex, so it works across processes. Errors (value already
/// changed, timeout, signal) all mean "look again", which the caller does.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(crate) fn futex_wait(word: &AtomicU64, expected: u32, timeout: Duration) {
    let ts = Timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    // SAFETY: FUTEX_WAIT reads the aligned 32-bit word at the address (inside a live atomic
    // word) and the timespec on this stack frame; it writes nothing.
    unsafe {
        syscall(
            SYS_FUTEX,
            futex_word(word),
            FUTEX_WAIT,
            expected,
            &ts as *const Timespec,
        );
    }
}

/// Wake one sleeper on the doorbell.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(crate) fn futex_wake(word: &AtomicU64) {
    // SAFETY: FUTEX_WAKE only uses the address as a key (inside a live atomic word).
    unsafe {
        syscall(SYS_FUTEX, futex_word(word), FUTEX_WAKE, 1 as c_int);
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) fn futex_wait(_word: &AtomicU64, _expected: u32, _timeout: Duration) {
    std::thread::sleep(Duration::from_micros(50));
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) fn futex_wake(_word: &AtomicU64) {}
