//! J3 tests: the vector corpus the Omega port must match, and the build of the Rust
//! reference itself. No test asserts a speed.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// FIPS 180-4 example messages with their published SHA-256 digests (NIST "Example
/// Algorithms", SHA256.pdf and SHA2_Additional, and FIPS 180-2 Appendix B).
const FIPS_SHA256: [(&[u8], &str); 4] = [
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
];

/// RFC 8032 section 7.1, TEST 1 to TEST 3: (secret key, public key, message, signature).
const RFC8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

const ALL_ACCEPT: Ed25519Verdict = Ed25519Verdict {
    key_decodes: true,
    verify: true,
    verify_strict: true,
};

fn has_ed25519(c: &[Vector], pk: [u8; 32], sig: [u8; 64], msg: &[u8]) -> Option<Ed25519Verdict> {
    c.iter().find_map(|v| match v {
        Vector::Ed25519 {
            public_key,
            signature,
            message,
            verdict,
        } if *public_key == pk && *signature == sig && message == msg => Some(*verdict),
        _ => None,
    })
}

/// The `sha2` 0.10 crate compiles its Armv8 SHA-2 instruction backend (with run-time
/// detection and the portable code as fallback) only when its `asm` feature is on
/// (`sha2/src/sha256.rs`). The resolved feature set is read from `cargo metadata`;
/// without cargo the test fails rather than passes.
#[test]
fn workspace_sha2_is_built_with_its_aarch64_instruction_backend() {
    let cargo = std::env::var("CARGO").expect("CARGO is unset: cannot read the resolved features");
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(repo_root().join("Cargo.toml"))
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed");
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["name"] == "sha2")
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(!ids.is_empty(), "sha2 not in the dependency graph");
    for node in meta["resolve"]["nodes"].as_array().unwrap() {
        if ids.contains(&node["id"].as_str().unwrap()) {
            let features: Vec<&str> = node["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            assert!(
                features.contains(&"asm"),
                "{} is built without its `asm` feature, so aarch64 uses the software backend (features: {features:?})",
                node["id"]
            );
        }
    }
    // The backend actually in use: linked into this binary and selected at run time.
    assert_sha2_backend(Backend::Instructions);
}

#[test]
fn published_sha256_answers_match_the_rust_crate_and_are_in_the_corpus() {
    let corpus = rust_corpus();
    for (msg, want) in FIPS_SHA256 {
        let want: [u8; 32] = unhex(want);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(msg)), want);
        assert!(
            corpus.contains(&Vector::Sha256 {
                message: msg.to_vec(),
                digest: want
            }),
            "FIPS message of {} bytes missing from the corpus",
            msg.len()
        );
    }
    // One million 'a' (FIPS 180-2 Appendix B.3): checked here only; too large to seal.
    assert_eq!(
        hex::encode(Sha256::digest(vec![b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn every_length_across_the_block_boundaries_is_in_the_corpus() {
    let corpus = rust_corpus();
    let lengths: Vec<usize> = corpus
        .iter()
        .filter_map(|v| match v {
            Vector::Sha256 { message, .. } => Some(message.len()),
            _ => None,
        })
        .collect();
    for len in 0..=257 {
        assert!(lengths.contains(&len), "no SHA-256 vector of {len} bytes");
    }
    // The Gate 4 change size and the A0 probe block.
    for len in [11_949, 16_384] {
        assert!(lengths.contains(&len), "no SHA-256 vector of {len} bytes");
    }
}

#[test]
fn rfc8032_vectors_match_the_rust_crate_and_are_in_the_corpus() {
    let corpus = rust_corpus();
    for (sk, pk, msg, sig) in RFC8032 {
        let key = SigningKey::from_bytes(&unhex(sk));
        let pk: [u8; 32] = unhex(pk);
        let sig: [u8; 64] = unhex(sig);
        let msg = hex::decode(msg).unwrap();
        assert_eq!(key.verifying_key().to_bytes(), pk);
        assert_eq!(key.sign(&msg).to_bytes(), sig);
        assert_eq!(
            has_ed25519(&corpus, pk, sig, &msg),
            Some(ALL_ACCEPT),
            "RFC 8032 vector missing or not accepted"
        );
    }
}

/// The corpus must pin the decisions where implementations differ: a small-order key
/// (accepted by `verify`, refused by `verify_strict`), a key that does not decode, a
/// non-canonical S (S + L), and a changed message.
#[test]
fn corpus_pins_the_edge_case_decisions() {
    let corpus = rust_corpus();
    let (pk, sig) = (unhex::<32>(RFC8032[0].1), unhex::<64>(RFC8032[0].3));

    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut small_sig = [0u8; 64];
    small_sig[..32].copy_from_slice(&identity);
    assert_eq!(
        has_ed25519(&corpus, identity, small_sig, SMALL_ORDER_MESSAGE),
        Some(Ed25519Verdict {
            key_decodes: true,
            verify: true,
            verify_strict: false
        }),
        "small-order key case missing or not split between verify and verify_strict"
    );

    // S + L, with L the order of the base point (RFC 8032 section 5.1), little endian.
    let l: [u8; 32] = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut s_plus_l = sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let t = sig[32 + i] as u16 + l[i] as u16 + carry;
        s_plus_l[32 + i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0);
    let v = has_ed25519(&corpus, pk, s_plus_l, b"").expect("non-canonical S case missing");
    assert!(v.key_decodes && !v.verify && !v.verify_strict, "{v:?}");

    let bad_key = corpus.iter().any(|v| {
        matches!(v, Vector::Ed25519 { verdict, .. } if *verdict == Ed25519Verdict {
            key_decodes: false, verify: false, verify_strict: false })
    });
    assert!(bad_key, "no key that fails to decode");

    let v = has_ed25519(&corpus, pk, sig, b"\x01").expect("changed-message case missing");
    assert!(v.key_decodes && !v.verify && !v.verify_strict, "{v:?}");
}

#[test]
fn every_corpus_answer_is_the_rust_crates_answer() {
    let corpus = rust_corpus();
    assert!(!corpus.is_empty());
    check_against_rust_crates(&corpus).unwrap();
    // A changed digest or verdict must be caught.
    let mut wrong = corpus.clone();
    match &mut wrong[0] {
        Vector::Sha256 { digest, .. } => digest[0] ^= 1,
        Vector::Ed25519 { verdict, .. } => verdict.verify = !verdict.verify,
    }
    assert_eq!(check_against_rust_crates(&wrong).unwrap_err().index, 0);
}

#[test]
fn corpus_round_trips_byte_for_byte() {
    let corpus = rust_corpus();
    let bytes = encode(&corpus);
    assert_eq!(&bytes[..8], &CORPUS_MAGIC);
    let back = decode(&bytes).unwrap();
    assert_eq!(back, corpus);
    assert_eq!(encode(&back), bytes);
}

#[test]
fn decoder_refuses_malformed_corpora_with_typed_errors() {
    let one = encode(&[
        sha256_vector(b"abc"),
        ed25519_vector(unhex(RFC8032[0].1), unhex(RFC8032[0].3), b""),
    ]);
    let reseal = |mut b: Vec<u8>| {
        let n = b.len() - 32;
        let sum: [u8; 32] = Sha256::digest(&b[..n]).into();
        b[n..].copy_from_slice(&sum);
        b
    };

    // Every strict prefix is refused (no panic, no partial result).
    for n in 0..one.len() {
        assert!(decode(&one[..n]).is_err(), "prefix of {n} bytes accepted");
    }
    let mut b = one.clone();
    b[0] ^= 1;
    assert_eq!(decode(&b), Err(CorpusError::BadMagic));
    let mut b = one.clone();
    b[8] = 2;
    assert_eq!(decode(&reseal(b)), Err(CorpusError::UnsupportedVersion(2)));
    let mut b = one.clone();
    b[10] = 1;
    assert_eq!(decode(&reseal(b)), Err(CorpusError::ReservedHeaderBits(1)));
    let mut b = one.clone();
    b[16] = 9;
    assert_eq!(
        decode(&reseal(b)),
        Err(CorpusError::UnknownKind { at: 16, kind: 9 })
    );
    // SHA record: 1 + 4 + 3 + 32 bytes; the Ed25519 verdict byte follows its kind.
    let ed_at = 16 + 1 + 4 + 3 + 32;
    let mut b = one.clone();
    b[ed_at + 1] |= 0x80;
    assert!(matches!(
        decode(&reseal(b)),
        Err(CorpusError::ReservedVerdictBits { .. })
    ));
    let mut b = one.clone();
    b[17..21].copy_from_slice(&(MAX_MESSAGE_BYTES + 1).to_le_bytes());
    assert_eq!(
        decode(&reseal(b)),
        Err(CorpusError::MessageTooLong {
            at: 17,
            len: MAX_MESSAGE_BYTES + 1
        })
    );
    let mut b = one.clone();
    b[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        decode(&reseal(b)),
        Err(CorpusError::TrailingBytes { .. })
    ));
    let mut b = one.clone();
    b[21] ^= 1; // one message bit, checksum left as it was
    assert_eq!(decode(&b), Err(CorpusError::ChecksumMismatch));
}

/// The sealed file is exactly what the Rust crates produce today, and decodes.
#[test]
fn sealed_corpus_matches_the_rust_crates_exactly() {
    let path = repo_root().join(CORPUS_PATH);
    let sealed = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let vectors = decode(&sealed).unwrap();
    check_against_rust_crates(&vectors).unwrap();
    assert!(
        sealed == encode(&rust_corpus()),
        "sealed corpus differs from the Rust crates' corpus"
    );
}

/// A second, independent SHA-256 (the A0 probe's own SHA-2 instruction code) gives
/// every corpus digest. On aarch64 the instructions must be present: a missing
/// instruction set fails the test instead of skipping it.
#[cfg(target_arch = "aarch64")]
#[test]
fn a0_instruction_code_gives_every_corpus_digest() {
    let corpus = rust_corpus();
    let mut n = 0;
    for v in &corpus {
        if let Vector::Sha256 { message, digest } = v {
            let got = crate::bounds::sha256_arm(message).expect("CPU SHA-2 instructions missing");
            assert_eq!(&got, digest, "length {}", message.len());
            n += 1;
        }
    }
    assert!(n > 0);
}

// ---------------------------------------------------------------------------------
// Which sha2 backend runs, and the portable fallback run automatically
// ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Instructions,
    Portable,
}

/// Path segment of `sha2::sha256::aarch64::sha256_compress` in both the legacy and
/// v0 symbol manglings, stored reversed so this constant cannot match itself in the
/// binary being searched.
const SHA2_AARCH64_SYMBOL_REVERSED: &[u8] = b"sserpmoc_652ahs5146hcraa7652ahs62ahs4";

/// `sha2` chooses its SHA-256 backend twice: at build time (the aarch64 module exists
/// only with `asm` and without `force-soft`) and at run time (`cpufeatures` checks the
/// `sha2` hwcap). Check both for this very test binary; any missing input fails.
fn assert_sha2_backend(want: Backend) {
    let exe = std::fs::read("/proc/self/exe").expect("read own executable");
    let symbol: Vec<u8> = SHA2_AARCH64_SYMBOL_REVERSED.iter().rev().copied().collect();
    let linked = exe.windows(symbol.len()).any(|w| w == symbol);
    #[cfg(target_arch = "aarch64")]
    let hwcap = std::arch::is_aarch64_feature_detected!("sha2");
    #[cfg(not(target_arch = "aarch64"))]
    let hwcap = false;
    let got = if linked && hwcap {
        Backend::Instructions
    } else {
        Backend::Portable
    };
    assert_eq!(
        got, want,
        "sha2 backend: instruction code linked = {linked}, CPU reports sha2 = {hwcap}"
    );
}

const INNER_ENV: &str = "SYNAPSE_J3_PORTABLE_INNER";

/// Run only inside the portable build started by
/// `portable_sha2_backend_gives_the_sealed_corpus`.
#[test]
fn inner_portable_backend_is_in_use() {
    if std::env::var_os(INNER_ENV).is_none() {
        return;
    }
    assert_sha2_backend(Backend::Portable);
}

/// Builds this crate a second time with `sha2/force-soft` (its portable backend; a
/// separate target directory, so no lock is shared with this run) and runs the
/// sealed-corpus test and the backend check there. sha2 0.10 fixes its backend at
/// build time, so the portable code cannot run inside this process.
#[test]
fn portable_sha2_backend_gives_the_sealed_corpus() {
    if std::env::var_os(INNER_ENV).is_some() {
        return;
    }
    let cargo = std::env::var("CARGO").expect("CARGO is unset: cannot build the portable variant");
    let out = Command::new(cargo)
        .current_dir(repo_root())
        .env(INNER_ENV, "1")
        .args([
            "test",
            "--offline",
            "-p",
            "synapse-bench",
            "--lib",
            "--features",
            "sha2/force-soft",
            "--target-dir",
        ])
        .arg(repo_root().join("target/j3-portable-sha2"))
        .args([
            "--",
            "--exact",
            "crypto_vectors::tests::sealed_corpus_matches_the_rust_crates_exactly",
            "crypto_vectors::tests::inner_portable_backend_is_in_use",
            "crypto_vectors::tests::every_corpus_answer_is_the_rust_crates_answer",
        ])
        .output()
        .expect("run cargo test for the portable build");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 3 passed"),
        "portable build failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------------
// The sealed corpus is pinned
// ---------------------------------------------------------------------------------

#[test]
fn sealed_corpus_digest_is_pinned() {
    assert_eq!(CORPUS_SHA256.len(), 64, "corpus digest not pinned");
    let sealed = std::fs::read(repo_root().join(CORPUS_PATH)).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&sealed)), CORPUS_SHA256);
    assert_eq!(
        hex::encode(Sha256::digest(encode(&rust_corpus()))),
        CORPUS_SHA256
    );
}

// ---------------------------------------------------------------------------------
// Ed25519 edge cases, each shown to separate a wrong implementation
// ---------------------------------------------------------------------------------

mod models {
    //! Independent models of the two `ed25519-dalek` checks, built on
    //! `curve25519-dalek`, and wrong variants of them. Each wrong variant differs from
    //! the right one in exactly one rule.
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;
    use sha2::{Digest, Sha512};

    pub type Check = fn(&[u8; 32], &[u8; 64], &[u8]) -> bool;

    fn k(r: &[u8], a: &[u8], m: &[u8]) -> Scalar {
        let mut h = Sha512::new();
        h.update(r);
        h.update(a);
        h.update(m);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    struct Parts {
        a: EdwardsPoint,
        r_bytes: [u8; 32],
        s_bytes: [u8; 32],
    }

    fn parts(pk: &[u8; 32], sig: &[u8; 64]) -> Option<Parts> {
        Some(Parts {
            a: CompressedEdwardsY(*pk).decompress()?,
            r_bytes: sig[..32].try_into().unwrap(),
            s_bytes: sig[32..].try_into().unwrap(),
        })
    }

    fn canonical_s(p: &Parts) -> Option<Scalar> {
        Option::from(Scalar::from_canonical_bytes(p.s_bytes))
    }

    /// [S]B - [k]A, with k over the encodings as given.
    fn r_prime(p: &Parts, pk: &[u8], s: &Scalar, m: &[u8]) -> EdwardsPoint {
        let k = k(&p.r_bytes, pk, m);
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-p.a, s)
    }

    fn small_order_r(p: &Parts) -> Option<bool> {
        Some(CompressedEdwardsY(p.r_bytes).decompress()?.is_small_order())
    }

    /// Model of `verify`: canonical S, cofactorless, R compared as bytes.
    pub fn verify(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            let s = canonical_s(&p)?;
            Some(r_prime(&p, pk, &s, m).compress().0 == p.r_bytes)
        })()
        .unwrap_or(false)
    }

    /// Model of `verify_strict`: `verify` plus R decodes and neither A nor R has small order.
    pub fn verify_strict(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            Some(!small_order_r(&p)? && !p.a.is_small_order() && verify(pk, sig, m))
        })()
        .unwrap_or(false)
    }

    /// WRONG: decodes R and compares points, so non-canonical R encodings pass.
    pub fn point_compare(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            let s = canonical_s(&p)?;
            let r = CompressedEdwardsY(p.r_bytes).decompress()?;
            Some(r_prime(&p, pk, &s, m) == r)
        })()
        .unwrap_or(false)
    }

    /// WRONG: cofactored equation [8]([S]B - [k]A - R) = 0.
    pub fn cofactored(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            let s = canonical_s(&p)?;
            let r = CompressedEdwardsY(p.r_bytes).decompress()?;
            Some((r_prime(&p, pk, &s, m) - r).mul_by_cofactor().is_identity())
        })()
        .unwrap_or(false)
    }

    /// WRONG: cofactored equation with the strict small-order checks.
    pub fn cofactored_strict(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            Some(!small_order_r(&p)? && !p.a.is_small_order() && cofactored(pk, sig, m))
        })()
        .unwrap_or(false)
    }

    /// WRONG: reduces S modulo L instead of refusing S >= L.
    pub fn s_mod_l(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            let s = Scalar::from_bytes_mod_order(p.s_bytes);
            Some(r_prime(&p, pk, &s, m).compress().0 == p.r_bytes)
        })()
        .unwrap_or(false)
    }

    /// WRONG: hashes the re-encoded (canonical) A instead of the bytes given.
    pub fn canonical_a_in_hash(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        (|| {
            let p = parts(pk, sig)?;
            let s = canonical_s(&p)?;
            let a = p.a.compress().0;
            Some(r_prime(&p, &a, &s, m).compress().0 == p.r_bytes)
        })()
        .unwrap_or(false)
    }

    /// WRONG: also refuses keys with a small-order component (not torsion free).
    pub fn torsion_free_key(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        parts(pk, sig).is_some_and(|p| p.a.is_torsion_free()) && verify(pk, sig, m)
    }

    /// WRONG as `verify_strict`: checks A for small order but not R.
    pub fn strict_without_r_check(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        parts(pk, sig).is_some_and(|p| !p.a.is_small_order()) && verify(pk, sig, m)
    }

    /// WRONG as `verify_strict`: no small-order checks at all.
    pub fn strict_without_small_order_checks(pk: &[u8; 32], sig: &[u8; 64], m: &[u8]) -> bool {
        verify(pk, sig, m)
    }
}

#[derive(Debug, Clone, Copy)]
enum Call {
    Verify,
    VerifyStrict,
}

/// Every edge case, the wrong implementation it catches, and the dalek decision it
/// is compared with. Cases follow the classes of Chalkias, Garillot and Nikolaenko,
/// "Taming the many EdDSAs" (SSR 2020, IACR ePrint 2020/1244): small-order A and R,
/// non-canonical A and R, mixed-order A and R, S >= L, and the cofactored versus
/// cofactorless split.
const SEPARATIONS: [(&str, &str, models::Check, Call); 10] = [
    (
        "noncanonical_r_y_p_plus_1",
        "point compare",
        models::point_compare,
        Call::Verify,
    ),
    (
        "noncanonical_r_negative_zero",
        "point compare",
        models::point_compare,
        Call::Verify,
    ),
    (
        "noncanonical_a_y_p",
        "canonical A in hash",
        models::canonical_a_in_hash,
        Call::Verify,
    ),
    (
        "small_order_a_and_r",
        "no small-order checks",
        models::strict_without_small_order_checks,
        Call::VerifyStrict,
    ),
    (
        "small_order_r_valid_key",
        "no small-order R check",
        models::strict_without_r_check,
        Call::VerifyStrict,
    ),
    (
        "mixed_order_a_k_not_multiple_of_8",
        "cofactored",
        models::cofactored,
        Call::Verify,
    ),
    (
        "mixed_order_a_k_multiple_of_8",
        "torsion-free key check",
        models::torsion_free_key,
        Call::Verify,
    ),
    (
        "mixed_order_r",
        "cofactored",
        models::cofactored,
        Call::Verify,
    ),
    (
        "mixed_order_r",
        "cofactored strict",
        models::cofactored_strict,
        Call::VerifyStrict,
    ),
    (
        "noncanonical_s_plus_l",
        "S reduced mod L",
        models::s_mod_l,
        Call::Verify,
    ),
];

/// The right models reproduce dalek on every corpus record, so a disagreement of a
/// wrong model is due to its one changed rule.
#[test]
fn models_reproduce_dalek_on_the_whole_corpus() {
    let mut n = 0;
    for v in rust_corpus() {
        if let Vector::Ed25519 {
            public_key,
            signature,
            message,
            verdict,
        } = v
        {
            assert_eq!(
                models::verify(&public_key, &signature, &message),
                verdict.verify
            );
            assert_eq!(
                models::verify_strict(&public_key, &signature, &message),
                verdict.verify_strict
            );
            n += 1;
        }
    }
    assert!(n > 0);
}

#[test]
fn each_edge_case_is_in_the_corpus_and_catches_a_wrong_implementation() {
    let corpus = rust_corpus();
    let cases = ed25519_edge_cases();
    for (name, wrong_name, wrong, call) in SEPARATIONS {
        let (_, v) = cases
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("edge case {name} missing"));
        assert!(corpus.contains(v), "{name} not in the corpus");
        let Vector::Ed25519 {
            public_key,
            signature,
            message,
            verdict,
        } = v
        else {
            panic!("{name} is not an Ed25519 case");
        };
        let right = match call {
            Call::Verify => verdict.verify,
            Call::VerifyStrict => verdict.verify_strict,
        };
        assert_ne!(
            wrong(public_key, signature, message),
            right,
            "{name}: the {wrong_name} implementation gives dalek's {call:?} answer"
        );
        // The wrong implementation is otherwise right: it accepts RFC 8032 TEST 1.
        let (pk, sig) = (unhex::<32>(RFC8032[0].1), unhex::<64>(RFC8032[0].3));
        assert!(
            wrong(&pk, &sig, b""),
            "{wrong_name} refuses RFC 8032 TEST 1"
        );
    }
    for (name, _) in &cases {
        assert!(
            SEPARATIONS.iter().any(|s| s.0 == *name),
            "edge case {name} has no separating implementation"
        );
    }
}
