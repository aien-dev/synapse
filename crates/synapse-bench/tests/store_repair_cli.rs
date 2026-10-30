//! `synapse-bench store-repair` (issue #105) through the real binary: report mode never
//! writes, and a write is refused unless it names one action, an operator key and a
//! backup. The repair itself (roll forward, adopt, signed log) is covered by the
//! `r1_repair_*` tests in `synapse-store`.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use synapse_store::blockdev::{BlockDevice, BlockDeviceConfig, FormatPolicy};

fn temp_dir(label: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "synapse-store-repair-cli-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A formatted, empty 16 MiB store in a regular file.
fn formatted_device(dir: &Path) -> PathBuf {
    let path = dir.join("raw.device");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(16 << 20).unwrap();
    f.sync_all().unwrap();
    let cfg = BlockDeviceConfig {
        path: path.clone(),
        format: FormatPolicy::FormatIfBlank,
        meta_region_bytes: 1 << 20,
        allow_foreign_signature: false,
    };
    drop(BlockDevice::open_path(&cfg, 64 * 1024).unwrap());
    path
}

fn sha(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).unwrap()).to_vec()
}

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_synapse-bench"))
        .arg("store-repair")
        .args(args)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn store_repair_cli_reports_and_refuses_writes_without_intent() {
    let dir = temp_dir("intent");
    let dev = formatted_device(&dir);
    let d = dev.to_str().unwrap();
    let key = dir.join("operator.key");
    std::fs::write(&key, format!("{}\n", "0b".repeat(32))).unwrap();
    let k = key.to_str().unwrap();
    let backup = dir.join("backup.bin");
    let b = backup.to_str().unwrap();
    let before = sha(&dev);

    // Report only: read-only, healthy, nothing written.
    let (ok, text) = run(&["--device", d]);
    assert!(ok, "{text}");
    assert!(text.contains("verdict: healthy"), "{text}");
    assert!(text.contains("repair history: none"), "{text}");

    // Refusals: no key, no backup, two actions, a key that is not 64 hex characters.
    let bad_key = dir.join("bad.key");
    std::fs::write(&bad_key, "not hex").unwrap();
    for (args, needle) in [
        (
            vec!["--device", d, "--roll-forward", "--backup", b],
            "--operator-key",
        ),
        (
            vec!["--device", d, "--roll-forward", "--operator-key", k],
            "--backup",
        ),
        (
            vec![
                "--device",
                d,
                "--roll-forward",
                "--adopt-older-checkpoint",
                "--operator-key",
                k,
                "--backup",
                b,
            ],
            "give one action",
        ),
        (
            vec![
                "--device",
                d,
                "--adopt-older-checkpoint",
                "--operator-key",
                bad_key.to_str().unwrap(),
                "--backup",
                b,
            ],
            "64 hex characters",
        ),
    ] {
        let (ok, text) = run(&args);
        assert!(!ok, "{args:?}: {text}");
        assert!(text.contains(needle), "{args:?}: {text}");
    }

    // With intent on a healthy device: nothing to do, nothing written, no backup.
    let (ok, text) = run(&[
        "--device",
        d,
        "--roll-forward",
        "--operator-key",
        k,
        "--backup",
        b,
    ]);
    assert!(ok, "{text}");
    assert!(text.contains("nothing was written"), "{text}");
    assert!(!backup.exists());
    assert_eq!(sha(&dev), before, "the device file changed");
    let _ = std::fs::remove_dir_all(&dir);
}
