//! Speed-of-light probe: what the storage stack and the CPU on this host can do at
//! best, measured with the same filesystem the store uses. Every probe is bounded
//! (a few seconds at most) and writes only inside the given directory.
//!
//! Storage probes time the syscalls a durable commit needs (append plus `fsync`,
//! append plus `fdatasync`, overwrite of already written blocks plus `fdatasync`,
//! `O_DIRECT | O_DSYNC` overwrite, one blob file with `fsync`, rename and directory
//! `fsync`), the same with 32 threads at once, and sequential bandwidth. CPU probes
//! time SHA-256, Ed25519, JSON, CRC-32C, and envelope validation on a typical
//! proposal. Energy comes from [`crate::energy`] (SoC package only; UNMEASURED when
//! the sensor is absent).

use crate::energy::{EnergyReading, EnergyWindow, Spbm};
use crate::stats::{round3, summarize_us, LatencySummary};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::time::{Duration, Instant};
use synapse_api::SubmitChangesetPayload;
use synapse_auth::{AgentCapabilityGrant, AuthenticatedRequest, Capability};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, FileMode, GitOid, IdempotencyKey,
    MutationOp, PathMutation, RepoId, SYNAPSE_ENVELOPE_VERSION,
};

/// Typical content bytes per proposal (Gate 4: 11,949 apparent bytes stored per proposal).
pub const TYPICAL_CONTENT_BYTES: usize = 12_000;

/// Target length of each CPU probe window (the energy counter updates every 0.1 s).
pub const CPU_PROBE_SECONDS: f64 = 3.0;

/// One timed probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub name: String,
    pub description: String,
    pub n: usize,
    /// Per-operation latency (milliseconds in the summary fields).
    pub latency: Option<LatencySummary>,
    pub energy: EnergyReading,
    /// SoC package joules per operation over the whole window (includes idle draw).
    pub pkg_j_per_op: Option<f64>,
    /// SoC package joules per operation above the idle baseline power.
    pub pkg_j_per_op_above_idle: Option<f64>,
    pub error: Option<String>,
}

/// Sequential write bandwidth (supporting data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bandwidth {
    pub name: String,
    pub bytes: u64,
    pub seconds: f64,
    pub seconds_per_gib: f64,
    pub error: Option<String>,
}

/// How often the energy counter changes value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterCadence {
    pub reads: usize,
    pub changes: usize,
    pub median_gap_ms: Option<f64>,
    pub min_gap_ms: Option<f64>,
    pub max_gap_ms: Option<f64>,
}

/// Full floor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloorReport {
    pub dir: String,
    pub iterations: usize,
    pub idle: EnergyReading,
    pub counter_cadence: Option<CounterCadence>,
    pub storage: Vec<Probe>,
    pub bandwidth: Vec<Bandwidth>,
    pub cpu: Vec<Probe>,
    pub typical_request_json_bytes: usize,
}

struct AlignedBuf {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

impl AlignedBuf {
    fn new(len: usize, fill: u8) -> Self {
        let layout = std::alloc::Layout::from_size_align(len, 4096).expect("layout");
        // SAFETY: layout has non-zero size; the pointer is checked and freed in Drop.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "aligned allocation failed");
        // SAFETY: `ptr` is valid for `len` bytes.
        unsafe { std::ptr::write_bytes(ptr, fill, len) };
        Self { ptr, layout }
    }
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `layout.size()` initialized bytes.
        unsafe { std::slice::from_raw_parts(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: allocated with the same layout in `new`.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn finish_probe(
    name: &str,
    description: &str,
    samples: Result<Vec<u64>, String>,
    energy: EnergyReading,
    idle: &EnergyReading,
) -> Probe {
    let (latency, n, error) = match samples {
        Ok(s) => (summarize_us(&s), s.len(), None),
        Err(e) => (None, 0, Some(e)),
    };
    let per_op = |j: Option<f64>| j.filter(|_| n > 0).map(|j| j / n as f64);
    let above = energy
        .pkg_above_idle_j(idle)
        .filter(|_| n > 0)
        .map(|j| j / n as f64);
    Probe {
        name: name.into(),
        description: description.into(),
        n,
        latency,
        pkg_j_per_op: per_op(energy.pkg_j),
        pkg_j_per_op_above_idle: above,
        energy,
        error,
    }
}

fn timed_loop(
    n: usize,
    mut op: impl FnMut(usize) -> Result<(), String>,
) -> (Result<Vec<u64>, String>, EnergyReading) {
    let w = EnergyWindow::start();
    let mut out = Vec::with_capacity(n);
    let mut err = None;
    for i in 0..n {
        let t = Instant::now();
        if let Err(e) = op(i) {
            err = Some(e);
            break;
        }
        out.push(t.elapsed().as_nanos() as u64 / 1000);
    }
    let e = w.finish();
    (err.map_or(Ok(out), Err), e)
}

fn storage_probes(dir: &Path, n: usize, idle: &EnergyReading) -> Vec<Probe> {
    let mut probes = Vec::new();
    let block = vec![0x5au8; 4096];

    // 1 and 2: append 4 KiB, then fsync or fdatasync.
    for (name, data_only) in [("append_4k_fsync", false), ("append_4k_fdatasync", true)] {
        let path = dir.join(format!("{name}.dat"));
        let res = (|| {
            let mut f = io(
                OpenOptions::new().create(true).append(true).open(&path),
                "open",
            )?;
            Ok(timed_loop(n, |_| {
                io(f.write_all(&block), "write")?;
                if data_only {
                    io(f.sync_data(), "fdatasync")
                } else {
                    io(f.sync_all(), "fsync")
                }
            }))
        })();
        let desc = if data_only {
            "append 4 KiB to a growing file, then fdatasync (size change needs a journal commit)"
        } else {
            "append 4 KiB to a growing file, then fsync (today's WAL pattern per frame)"
        };
        probes.push(match res {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        });
        let _ = fs::remove_file(&path);
    }

    // 3 and 4: overwrite blocks that were already written and synced.
    let pre = dir.join("prewritten.dat");
    let prewrite = (|| {
        let mut f = io(File::create(&pre), "create prewritten")?;
        let chunk = vec![0u8; 1 << 20];
        let total = (n * 4096).div_ceil(1 << 20) + 1;
        for _ in 0..total {
            io(f.write_all(&chunk), "prewrite")?;
        }
        io(f.sync_all(), "prewrite fsync")
    })();
    let name = "overwrite_4k_fdatasync";
    let desc = "overwrite 4 KiB inside an already written, synced file, then fdatasync (no metadata change)";
    probes.push(
        match prewrite.clone().and_then(|_| {
            let f = io(OpenOptions::new().write(true).open(&pre), "open")?;
            Ok(timed_loop(n, |i| {
                io(f.write_at(&block, (i * 4096) as u64), "pwrite")?;
                io(f.sync_data(), "fdatasync")
            }))
        }) {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        },
    );
    let name = "odirect_dsync_4k_overwrite";
    let desc = "O_DIRECT | O_DSYNC 4 KiB overwrite inside an already written file (device write with FUA or flush)";
    let abuf = AlignedBuf::new(4096, 0xa5);
    probes.push(
        match prewrite.and_then(|_| {
            let f = io(
                OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_DIRECT | libc::O_DSYNC)
                    .open(&pre),
                "open O_DIRECT",
            )?;
            Ok(timed_loop(n, |i| {
                io(
                    f.write_at(abuf.as_slice(), (i * 4096) as u64),
                    "pwrite O_DIRECT",
                )
                .map(|_| ())
            }))
        }) {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        },
    );
    let _ = fs::remove_file(&pre);

    // Batch-size dependence when writing into already written space (64 MiB pre-written).
    let pre = dir.join("prewritten64.dat");
    let prewrite = (|| {
        let mut f = io(File::create(&pre), "create prewritten")?;
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..64 {
            io(f.write_all(&chunk), "prewrite")?;
        }
        io(f.sync_all(), "prewrite fsync")
    })();
    for (name, size) in [
        ("overwrite_64k_fdatasync", 64usize << 10),
        ("overwrite_1m_fdatasync", 1 << 20),
    ] {
        let desc = format!(
            "overwrite {} KiB inside an already written, synced file, then fdatasync",
            size >> 10
        );
        let buf = vec![0x6du8; size];
        let slots = (64usize << 20) / size;
        probes.push(
            match prewrite.clone().and_then(|_| {
                let f = io(OpenOptions::new().write(true).open(&pre), "open")?;
                Ok(timed_loop(n / 3, |i| {
                    io(f.write_at(&buf, ((i % slots) * size) as u64), "pwrite")?;
                    io(f.sync_data(), "fdatasync")
                }))
            }) {
                Ok((s, e)) => finish_probe(name, &desc, s, e, idle),
                Err(e) => finish_probe(name, &desc, Err(e), EnergyReading::default(), idle),
            },
        );
    }
    let _ = fs::remove_file(&pre);

    // fallocate leaves unwritten extents: does the first write into them cost a journal commit?
    let name = "fallocate_4k_overwrite_fdatasync";
    let desc = "write 4 KiB into fallocate()d (unwritten) space, then fdatasync";
    let fpath = dir.join("fallocated.dat");
    probes.push(
        match (|| {
            let f = io(
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(&fpath),
                "create",
            )?;
            let len = (n * 4096) as libc::off_t;
            // SAFETY: valid fd from `f`; mode 0 allocates blocks and extends the size.
            let rc = unsafe { libc::fallocate(std::os::fd::AsRawFd::as_raw_fd(&f), 0, 0, len) };
            if rc != 0 {
                return Err(format!("fallocate: {}", std::io::Error::last_os_error()));
            }
            io(f.sync_all(), "fsync after fallocate")?;
            Ok(timed_loop(n, |i| {
                io(f.write_at(&block, (i * 4096) as u64), "pwrite")?;
                io(f.sync_data(), "fdatasync")
            }))
        })() {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        },
    );
    let _ = fs::remove_file(&fpath);

    // Cost of pre-writing WAL space (zeros, then fsync), per 64 MiB chunk.
    let name = "prewrite_64m_zeros_fsync";
    let desc = "extend a file by 64 MiB of zeros, then fsync (WAL segment pre-writing, amortized)";
    let zpath = dir.join("zeros.dat");
    let zeros = vec![0u8; 1 << 20];
    probes.push(
        match (|| {
            let mut f = io(
                OpenOptions::new().create(true).append(true).open(&zpath),
                "open",
            )?;
            Ok(timed_loop(5, |_| {
                for _ in 0..64 {
                    io(f.write_all(&zeros), "write zeros")?;
                }
                io(f.sync_all(), "fsync")
            }))
        })() {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        },
    );
    let _ = fs::remove_file(&zpath);

    // 5: size dependency of one append plus fdatasync.
    for (name, size) in [
        ("append_64k_fdatasync", 64 << 10),
        ("append_1m_fdatasync", 1 << 20),
    ] {
        let path = dir.join(format!("{name}.dat"));
        let buf = vec![0x3cu8; size];
        let desc = format!("append {} KiB, then fdatasync", size >> 10);
        let res = (|| {
            let mut f = io(
                OpenOptions::new().create(true).append(true).open(&path),
                "open",
            )?;
            Ok(timed_loop(n / 3, |_| {
                io(f.write_all(&buf), "write")?;
                io(f.sync_data(), "fdatasync")
            }))
        })();
        probes.push(match res {
            Ok((s, e)) => finish_probe(name, &desc, s, e, idle),
            Err(e) => finish_probe(name, &desc, Err(e), EnergyReading::default(), idle),
        });
        let _ = fs::remove_file(&path);
    }

    // 6: today's per-blob durable path.
    let blobs = dir.join("blobs");
    let content = vec![0x77u8; TYPICAL_CONTENT_BYTES];
    let name = "blob_file_create_fsync_rename_dirfsync_12k";
    let desc = "new 12 KB blob file: create tmp, write, fsync, rename, fsync shard directory (today's write_blob_file)";
    let res = (|| {
        for s in 0..16 {
            io(
                fs::create_dir_all(blobs.join(format!("{s:02x}"))),
                "mkdir shard",
            )?;
        }
        Ok(timed_loop(n, |i| {
            let shard = blobs.join(format!("{:02x}", i % 16));
            let tmp = shard.join(format!("b{i}.tmp"));
            let mut f = io(File::create(&tmp), "create")?;
            io(f.write_all(&content), "write")?;
            io(f.sync_all(), "fsync")?;
            drop(f);
            io(fs::rename(&tmp, shard.join(format!("b{i}"))), "rename")?;
            io(File::open(&shard).and_then(|d| d.sync_all()), "dir fsync")
        }))
    })();
    probes.push(match res {
        Ok((s, e)) => finish_probe(name, desc, s, e, idle),
        Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
    });
    let _ = fs::remove_dir_all(&blobs);

    // 7: 32 threads at once, each with its own file (does the kernel merge syncs?).
    for (name, blob_pattern) in [
        ("concurrent_32_append_4k_fdatasync_round", false),
        ("concurrent_32_blob_file_create_round", true),
    ] {
        let threads = 32usize;
        let rounds = (n / 10).max(10);
        let root = dir.join(name);
        let desc = if blob_pattern {
            "32 threads each create one 12 KB blob file with fsync, rename, directory fsync; time per round (all 32 done)"
        } else {
            "32 threads each append 4 KiB to their own file and fdatasync; time per round (all 32 done)"
        };
        let res = (|| -> Result<(Result<Vec<u64>, String>, EnergyReading), String> {
            io(fs::create_dir_all(&root), "mkdir")?;
            let start = Barrier::new(threads + 1);
            let end = Barrier::new(threads + 1);
            let w = EnergyWindow::start();
            let mut samples = Vec::with_capacity(rounds);
            let errs: Vec<String> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..threads)
                    .map(|t| {
                        let (start, end, root, block, content) =
                            (&start, &end, &root, &block, &content);
                        s.spawn(move || -> Result<(), String> {
                            let shard = root.join(format!("{:02x}", t % 16));
                            io(fs::create_dir_all(&shard), "mkdir")?;
                            let mut log = io(
                                OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(root.join(format!("t{t}.log"))),
                                "open",
                            )?;
                            let mut first_err = None;
                            for r in 0..rounds {
                                start.wait();
                                let res = if blob_pattern {
                                    (|| {
                                        let tmp = shard.join(format!("t{t}r{r}.tmp"));
                                        let mut f = io(File::create(&tmp), "create")?;
                                        io(f.write_all(content), "write")?;
                                        io(f.sync_all(), "fsync")?;
                                        drop(f);
                                        io(
                                            fs::rename(&tmp, shard.join(format!("t{t}r{r}"))),
                                            "rename",
                                        )?;
                                        io(
                                            File::open(&shard).and_then(|d| d.sync_all()),
                                            "dir fsync",
                                        )
                                    })()
                                } else {
                                    io(log.write_all(block), "write")
                                        .and_then(|_| io(log.sync_data(), "fdatasync"))
                                };
                                if let (Err(e), None) = (res, &first_err) {
                                    first_err = Some(e);
                                }
                                end.wait();
                            }
                            first_err.map_or(Ok(()), Err)
                        })
                    })
                    .collect();
                for _ in 0..rounds {
                    start.wait();
                    let t = Instant::now();
                    end.wait();
                    samples.push(t.elapsed().as_nanos() as u64 / 1000);
                }
                handles
                    .into_iter()
                    .filter_map(|h| h.join().ok().and_then(|r| r.err()))
                    .collect()
            });
            let e = w.finish();
            Ok((errs.into_iter().next().map_or(Ok(samples), Err), e))
        })();
        probes.push(match res {
            Ok((s, e)) => finish_probe(name, desc, s, e, idle),
            Err(e) => finish_probe(name, desc, Err(e), EnergyReading::default(), idle),
        });
        let _ = fs::remove_dir_all(&root);
    }
    probes
}

fn bandwidth_probes(dir: &Path) -> Vec<Bandwidth> {
    const TOTAL: usize = 256 << 20;
    const CHUNK: usize = 1 << 20;
    let mut out = Vec::new();
    let path = dir.join("bandwidth.dat");
    let buffered = (|| {
        let mut f = io(File::create(&path), "create")?;
        let buf = vec![0x11u8; CHUNK];
        let t = Instant::now();
        for _ in 0..TOTAL / CHUNK {
            io(f.write_all(&buf), "write")?;
        }
        io(f.sync_all(), "fsync")?;
        Ok(t.elapsed().as_secs_f64())
    })();
    let _ = fs::remove_file(&path);
    let direct = (|| {
        let f = io(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .custom_flags(libc::O_DIRECT)
                .open(&path),
            "open O_DIRECT",
        )?;
        let buf = AlignedBuf::new(CHUNK, 0x22);
        let t = Instant::now();
        for i in 0..TOTAL / CHUNK {
            io(f.write_at(buf.as_slice(), (i * CHUNK) as u64), "pwrite")?;
        }
        io(f.sync_all(), "fsync")?;
        Ok(t.elapsed().as_secs_f64())
    })();
    let _ = fs::remove_file(&path);
    for (name, r) in [
        ("sequential_buffered_1m_writes_then_fsync", buffered),
        ("sequential_odirect_1m_writes_then_fsync", direct),
    ] {
        let (seconds, error) = match r {
            Ok(s) => (s, None),
            Err(e) => (0.0, Some(e)),
        };
        out.push(Bandwidth {
            name: name.into(),
            bytes: TOTAL as u64,
            seconds: round3(seconds * 1000.0) / 1000.0,
            seconds_per_gib: if seconds > 0.0 {
                seconds * (1u64 << 30) as f64 / TOTAL as f64
            } else {
                0.0
            },
            error,
        });
    }
    out
}

/// A typical signed submit request (two upserted files, 12 KB of content).
pub fn typical_request() -> AuthenticatedRequest<SubmitChangesetPayload> {
    let authority = SigningKey::from_bytes(&[3u8; 32]);
    let agent = SigningKey::from_bytes(&[4u8; 32]);
    let agent_did = encode_did_key_ed25519(&agent.verifying_key().to_bytes());
    let repo = RepoId::new("aien-spark/aien-sovereign-core").expect("repo id");
    let grant = AgentCapabilityGrant::issue(
        &authority,
        [9u8; 32],
        repo.clone(),
        agent_did.clone(),
        vec![Capability::Read, Capability::Propose],
        1 << 30,
        u32::MAX,
        60_000,
        0,
        u64::MAX / 2,
    );
    let mut blobs = Vec::new();
    let mut mutations = Vec::new();
    for (i, path) in ["src/a.rs", "src/b.rs"].iter().enumerate() {
        let content: Vec<u8> = (0..TYPICAL_CONTENT_BYTES / 2)
            .map(|j| b"pub fn x() {}\n"[(j + i) % 14])
            .collect();
        let digest = BlobDigest::compute(&content);
        mutations.push(PathMutation {
            path: path.to_string(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: digest,
                size_bytes: content.len() as u64,
            },
        });
        blobs.push((digest, content));
    }
    let mut envelope = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: repo.clone(),
        base_git_oid: GitOid::compute_blob(b"base"),
        parent_changesets: vec![],
        author_did: agent_did,
        idempotency_key: IdempotencyKey::from_label("floor"),
        created_at_ms: 1,
        intent_summary: "floor probe".into(),
        mutations,
        evidence_receipts: vec![],
        signature: vec![],
    };
    envelope.sign(&agent);
    AuthenticatedRequest::sign_new(
        &agent,
        grant,
        repo,
        Capability::Propose,
        [7u8; 32],
        1,
        0,
        SubmitChangesetPayload { envelope, blobs },
    )
    .expect("sign request")
}

fn cpu_probes(n: usize, idle: &EnergyReading) -> (Vec<Probe>, usize) {
    let mut probes = Vec::new();
    let req = typical_request();
    let wire = serde_json::to_vec(&req).expect("encode");
    let wire_len = wire.len();
    let payload_buf = vec![0x42u8; wire_len];
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let msg = vec![0x10u8; 256];
    let sig = key.sign(&msg);
    let vk = key.verifying_key();

    // Each CPU probe runs for about CPU_PROBE_SECONDS so the 0.1 s energy counter
    // resolves it; `iters` only sizes the calibration pass.
    let mut push = |name: &str, desc: &str, iters: usize, f: &mut dyn FnMut()| {
        let calib = Instant::now();
        for _ in 0..iters.clamp(10, 200) {
            f();
        }
        let per = calib.elapsed().as_secs_f64() / iters.clamp(10, 200) as f64;
        let n = ((CPU_PROBE_SECONDS / per.max(1e-9)) as usize).clamp(iters, 5_000_000);
        let (s, e) = timed_loop(n, |_| {
            f();
            Ok(())
        });
        probes.push(finish_probe(name, desc, s, e, idle));
    };
    push(
        "sha256_request_sized",
        "SHA-256 over a buffer the size of a typical JSON submit request",
        n,
        &mut || {
            std::hint::black_box(Sha256::digest(std::hint::black_box(&payload_buf)));
        },
    );
    push(
        "sha256_content_12k",
        "SHA-256 over 12 KB (typical content per proposal)",
        n,
        &mut || {
            std::hint::black_box(Sha256::digest(std::hint::black_box(
                &payload_buf[..TYPICAL_CONTENT_BYTES],
            )));
        },
    );
    push(
        "ed25519_verify",
        "one Ed25519 signature verification (256-byte message)",
        n,
        &mut || {
            std::hint::black_box(vk.verify(std::hint::black_box(&msg), &sig).is_ok());
        },
    );
    push(
        "ed25519_sign",
        "one Ed25519 signature (256-byte message)",
        n,
        &mut || {
            std::hint::black_box(key.sign(std::hint::black_box(&msg)));
        },
    );
    push(
        "json_encode_submit_request",
        "serde_json encode of a typical signed submit request",
        n,
        &mut || {
            std::hint::black_box(serde_json::to_vec(std::hint::black_box(&req)).ok());
        },
    );
    push(
        "json_decode_submit_request",
        "serde_json decode of a typical signed submit request",
        n,
        &mut || {
            let r: Option<AuthenticatedRequest<SubmitChangesetPayload>> =
                serde_json::from_slice(std::hint::black_box(&wire)).ok();
            std::hint::black_box(r);
        },
    );
    push(
        "auth_payload_digest",
        "synapse-auth payload digest: serde_json encode of the payload plus SHA-256",
        n,
        &mut || {
            let bytes = serde_json::to_vec(&req.payload).unwrap_or_default();
            std::hint::black_box(Sha256::digest(&bytes));
        },
    );
    push(
        "envelope_validate",
        "ChangesetEnvelope::validate (canonical bytes, path rules, Ed25519 verify, id digest)",
        n,
        &mut || {
            std::hint::black_box(req.payload.envelope.validate().ok());
        },
    );
    push(
        "blob_digest_12k",
        "BlobDigest::compute over 12 KB of content",
        n,
        &mut || {
            std::hint::black_box(BlobDigest::compute(std::hint::black_box(
                &payload_buf[..TYPICAL_CONTENT_BYTES],
            )));
        },
    );
    push(
        "crc32c_request_sized",
        "synapse_store::crc32c over a request-sized buffer",
        (n / 10).max(10),
        &mut || {
            std::hint::black_box(synapse_store::crc32c(std::hint::black_box(&payload_buf)));
        },
    );
    (probes, wire_len)
}

fn counter_cadence() -> Option<CounterCadence> {
    let s = Spbm::find()?;
    let start = Instant::now();
    let mut last = s.energy_uj("pkg")?;
    let mut last_change = Instant::now();
    let mut gaps = Vec::new();
    let mut reads = 0usize;
    while start.elapsed() < Duration::from_secs(1) {
        let v = s.energy_uj("pkg")?;
        reads += 1;
        if v != last {
            gaps.push(last_change.elapsed().as_micros() as u64);
            last_change = Instant::now();
            last = v;
        }
    }
    let changes = gaps.len();
    // The first gap starts at an arbitrary phase; drop it.
    let gaps: Vec<u64> = gaps.into_iter().skip(1).collect();
    let sum = summarize_us(&gaps);
    Some(CounterCadence {
        reads,
        changes,
        median_gap_ms: sum.as_ref().map(|s| s.p50_ms),
        min_gap_ms: sum.as_ref().map(|s| s.min_ms),
        max_gap_ms: sum.as_ref().map(|s| s.max_ms),
    })
}

/// Run every probe inside `dir` (created, then removed) and return the report.
pub fn run_floor(dir: &Path, iterations: usize) -> Result<FloorReport, String> {
    let dir: PathBuf = dir.join(format!("synapse-floor-{}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let idle = crate::energy::idle_window(Duration::from_secs(5));
    let counter_cadence = counter_cadence();
    let storage = storage_probes(&dir, iterations, &idle);
    let bandwidth = bandwidth_probes(&dir);
    let (cpu, typical_request_json_bytes) = cpu_probes(iterations * 4, &idle);
    let _ = fs::remove_dir_all(&dir);
    Ok(FloorReport {
        dir: dir.display().to_string(),
        iterations,
        idle,
        counter_cadence,
        storage,
        bandwidth,
        cpu,
        typical_request_json_bytes,
    })
}
