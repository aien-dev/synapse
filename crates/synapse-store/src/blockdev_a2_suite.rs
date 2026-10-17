//! The A2 crash suite (`segment_tests.rs`, compiled here a second time, unchanged)
//! against the R1 raw block store.
//!
//! The suite reaches the store through `super::*`, so this module provides what it
//! names: `tests::temp_store_dir` makes a store directory holding a zero-filled device
//! file ([`blockdev_tests::TEST_DEVICE_FILE`]), which [`SynapseStore::open`] opens as a
//! raw block store (the crash children, which run the original `segment_tests` module,
//! reopen through the same hook). `fs` and `segment` give the suite's file-level
//! damage (read, overwrite, empty, or delete a segment file; list segments and index
//! files) its device meaning: a segment file is the data area of a committed or
//! headed slot, deleting it erases the slot header, and the small files are the
//! device's named metadata objects. Everything else passes through to `std::fs`.
//!
//! Limit: the pre-A2 upgrade test copies directory fixtures (there are no pre-A2 raw
//! block stores), so in this module it exercises the directory store again.

use super::*;

// Compiled a second time on purpose: the suite runs unchanged against the device.
#[allow(clippy::duplicate_mod)]
#[path = "segment_tests.rs"]
mod segment_tests;

/// Open the device in `dir`, if `dir` is a raw block test store.
fn device_in(dir: &Path) -> Option<Arc<blockdev::BlockDevice>> {
    let mut cfg = blockdev_tests::redirect(dir)?;
    cfg.format = FormatPolicy::OpenExisting;
    Some(blockdev::BlockDevice::open_path_unlocked(&cfg).expect("open the test device"))
}

use std::sync::Arc;

pub(crate) mod tests {
    pub(crate) use crate::tests::make_signed_changeset;
    use std::path::PathBuf;

    /// A new store directory holding a zero-filled raw device file.
    pub(crate) fn temp_store_dir(label: &str) -> PathBuf {
        let dir = crate::tests::temp_store_dir(&format!("r1dev-{label}"));
        crate::blockdev_tests::make_device_file(
            &dir.join(crate::blockdev_tests::TEST_DEVICE_FILE),
            crate::blockdev_tests::TEST_DEVICE_BYTES,
        );
        dir
    }
}

pub(crate) mod segment {
    pub(crate) use crate::segment::*;
    use crate::SynapseResult;
    use std::path::Path;

    /// Segment ids present: on the device in `dir`, or as files.
    pub(crate) fn list_segments(dir: &Path) -> SynapseResult<Vec<u64>> {
        match super::device_in(dir) {
            Some(dev) => Ok(dev.list_segments().expect("list device segments")),
            None => crate::segment::list_segments(dir),
        }
    }
}

pub(crate) mod fs {
    use std::ffi::OsString;
    pub(crate) use std::fs::{read_to_string, remove_dir_all};
    use std::io::{Error, ErrorKind, Result};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    enum Target {
        Segment(Arc<crate::blockdev::BlockDevice>, u64),
        Object(Arc<crate::blockdev::BlockDevice>, String),
        Plain,
    }

    fn target(p: &Path) -> Target {
        let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
            return Target::Plain;
        };
        if name == crate::blockdev_tests::TEST_DEVICE_FILE || name == "acks.txt" {
            return Target::Plain;
        }
        let Some(dev) = super::device_in(dir) else {
            return Target::Plain;
        };
        match crate::segment::parse_segment_file_name(name) {
            Some(id) => Target::Segment(dev, id),
            None => Target::Object(dev, name.to_string()),
        }
    }

    fn not_found(p: &Path) -> Error {
        Error::new(
            ErrorKind::NotFound,
            format!("{} not on the device", p.display()),
        )
    }

    pub(crate) fn read(p: impl AsRef<Path>) -> Result<Vec<u8>> {
        let p = p.as_ref();
        match target(p) {
            Target::Segment(dev, id) => {
                if !dev.header_valid(id)? {
                    return Err(not_found(p));
                }
                let len = dev.geometry().segment_bytes as u32;
                dev.read_segment_at(id, 0, len)
            }
            Target::Object(dev, name) => dev.read_named(&name).ok_or_else(|| not_found(p)),
            Target::Plain => std::fs::read(p),
        }
    }

    /// Overwrite a segment's data area from byte 0 (the rest zeroed) and flush; give it a
    /// header if it has none.
    pub(crate) fn write(p: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> Result<()> {
        let (p, bytes) = (p.as_ref(), bytes.as_ref());
        match target(p) {
            Target::Segment(dev, id) => {
                let mut data = bytes.to_vec();
                data.resize(dev.geometry().segment_bytes as usize, 0);
                if !dev.header_valid(id)? {
                    dev.write_segment_header(id)?;
                }
                dev.write_segment(id, 0, &data)?;
                dev.flush()
            }
            Target::Object(dev, name) => dev.write_named(&name, bytes),
            Target::Plain => std::fs::write(p, bytes),
        }
    }

    /// Delete a segment (erase its slot header) or a metadata object.
    pub(crate) fn remove_file(p: impl AsRef<Path>) -> Result<()> {
        let p = p.as_ref();
        match target(p) {
            Target::Segment(dev, id) => dev.erase_segment_header(id),
            Target::Object(dev, name) => {
                if dev.remove_named_where(|n| n == name)? {
                    Ok(())
                } else {
                    Err(not_found(p))
                }
            }
            Target::Plain => std::fs::remove_file(p),
        }
    }

    pub(crate) struct Entry {
        name: OsString,
        path: PathBuf,
        dir: bool,
    }

    pub(crate) struct Kind(bool);

    impl Kind {
        pub(crate) fn is_dir(&self) -> bool {
            self.0
        }
    }

    impl Entry {
        pub(crate) fn file_name(&self) -> OsString {
            self.name.clone()
        }
        pub(crate) fn path(&self) -> PathBuf {
            self.path.clone()
        }
        pub(crate) fn file_type(&self) -> Result<Kind> {
            Ok(Kind(self.dir))
        }
    }

    /// Directory listing; a raw block test store lists its device's objects and segments.
    pub(crate) fn read_dir(p: impl AsRef<Path>) -> Result<std::vec::IntoIter<Result<Entry>>> {
        let p = p.as_ref();
        let mut out = Vec::new();
        if let Some(dev) = super::device_in(p) {
            let mut names = dev.list_named();
            names.extend(
                dev.list_segments()?
                    .into_iter()
                    .map(crate::segment::segment_file_name),
            );
            for name in names {
                out.push(Ok(Entry {
                    path: p.join(&name),
                    name: name.into(),
                    dir: false,
                }));
            }
            return Ok(out.into_iter());
        }
        for e in std::fs::read_dir(p)? {
            let e = e?;
            out.push(Ok(Entry {
                name: e.file_name(),
                path: e.path(),
                dir: e.file_type()?.is_dir(),
            }));
        }
        Ok(out.into_iter())
    }
}

/// Control: the stores the suite opens here are raw block stores (no segment files,
/// no blob directory, no metadata files next to the device).
#[test]
fn r1_suite_stores_are_raw_block_stores() {
    let dir = tests::temp_store_dir("control");
    {
        let mut s = SynapseStore::open(
            &dir,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits {
                segment_bytes: 64 * 1024,
                ..StoreLimits::default()
            },
        )
        .unwrap();
        assert!(matches!(s.medium, Medium::Block(_)));
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let (env, blobs) =
            tests::make_signed_changeset(&key, "control", "src/c.rs", b"control", vec![], 1000);
        s.ingest_changeset(env, &blobs).unwrap();
        s.checkpoint_and_compact(1000).unwrap();
    }
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![blockdev_tests::TEST_DEVICE_FILE.to_string()]);
    let dev = device_in(&dir).unwrap();
    assert_eq!(dev.list_segments().unwrap(), vec![1]);
    assert!(dev.read_named("checkpoint.v2").is_some());
    assert!(dev.read_named("wal.log").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}
