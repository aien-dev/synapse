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
