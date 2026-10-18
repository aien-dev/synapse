//! ADR 0003 step M1: secret scanning at admission (section 5.13).
//!
//! Every planted secret below is assembled at run time from split pieces and a deterministic
//! generator, so this file itself holds no complete token and no real key. Values used as
//! negatives are clearly fake documentation examples.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use synapse_api::secret_scan::{
    check_blobs, scan, scan_with_steps, SecretRule, SECRET_RULESET_VERSION,
};
use synapse_api::{SubmitChangesetPayload, SynapseService, TreeTarget};
use synapse_auth::{
    AgentCapabilityGrant, AuthenticatedRequest, Capability, CapabilityChain, CapabilityLink,
    ChainQuotas, ChainedRequest, ChangeScope, LinkCaveats, OperationSet, PathScope, ReferenceKind,
    ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangeId, ChangesetEnvelope, ChangesetEnvelopeV2, FileMode,
    GitOid, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent, WalSeq,
    SYNAPSE_ENVELOPE_VERSION,
};
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits};

/// Deterministic xorshift generator for token bodies.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn from(&mut self, alphabet: &[u8], n: usize) -> String {
        (0..n)
            .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize] as char)
            .collect()
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DIGITS: &[u8] = b"0123456789";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `(rule, secret)` pairs; each secret is the exact sensitive span.
fn planted() -> Vec<(SecretRule, String)> {
    let mut g = Gen(0x9E37_79B9_7F4A_7C15);
    let dash5 = "-".repeat(5);
    let pem = |label: &str, g: &mut Gen| {
        let body: Vec<String> = (0..6).map(|_| g.from(B64, 64)).collect();
        format!(
            "{dash5}{} {label}{dash5}\n{}\n{dash5}END {label}{dash5}\n",
            "BEGIN",
            body.join("\n")
        )
    };
    let rsa = pem(&["RSA", "PRIVATE", "KEY"].join(" "), &mut g);
    let openssh = pem(&["OPENSSH", "PRIVATE", "KEY"].join(" "), &mut g);
    let pkcs8 = pem(&["PRIVATE", "KEY"].join(" "), &mut g);
    vec![
        (SecretRule::PrivateKeyBlock, rsa),
        (SecretRule::PrivateKeyBlock, openssh),
        (SecretRule::PrivateKeyBlock, pkcs8),
        (
            SecretRule::AwsAccessKeyId,
            format!("{}{}", ["AK", "IA"].concat(), g.from(UPPER_DIGIT, 16)),
        ),
        (
            SecretRule::AwsAccessKeyId,
            format!("{}{}", ["AS", "IA"].concat(), g.from(UPPER_DIGIT, 16)),
        ),
        (
            SecretRule::GithubToken,
            format!("{}{}", ["gh", "p_"].concat(), g.from(ALNUM, 36)),
        ),
        (
            SecretRule::GithubToken,
            format!("{}{}", ["gh", "s_"].concat(), g.from(ALNUM, 36)),
        ),
        (
            SecretRule::GithubFineGrainedToken,
            format!(
                "{}{}_{}",
                ["github", "_pat_"].concat(),
                g.from(ALNUM, 22),
                g.from(ALNUM, 59)
            ),
        ),
        (
            SecretRule::SlackToken,
            format!(
                "{}{}-{}-{}",
                ["xo", "xb-"].concat(),
                g.from(DIGITS, 12),
                g.from(DIGITS, 13),
                g.from(ALNUM, 24)
            ),
        ),
        (
            SecretRule::SlackWebhook,
            format!(
                "https://{}T{}/B{}/{}",
                ["hooks.", "slack.com/services/"].concat(),
                g.from(UPPER_DIGIT, 10),
                g.from(UPPER_DIGIT, 10),
                g.from(ALNUM, 24)
            ),
        ),
        (
            SecretRule::StripeLiveKey,
            format!("{}{}", ["sk_", "live_"].concat(), g.from(ALNUM, 32)),
        ),
        (
            SecretRule::AnthropicKey,
            format!("{}api03-{}", ["sk-", "ant-"].concat(), g.from(ALNUM, 93)),
        ),
        (
            SecretRule::OpenAiKey,
            format!("{}{}", ["sk-", "proj-"].concat(), g.from(ALNUM, 64)),
        ),
        (
            SecretRule::OpenAiKey,
            format!(
                "sk-{}{}{}",
                g.from(ALNUM, 20),
                ["T3Blbk", "FJ"].concat(),
                g.from(ALNUM, 20)
            ),
        ),
        (SecretRule::SecretAssignment, g.from(ALNUM, 40)),
    ]
}

/// The planted secret placed in a realistic source context.
fn in_context(rule: SecretRule, secret: &str) -> Vec<u8> {
    match rule {
        SecretRule::SecretAssignment => {
            format!("fn main() {{\n    let db_password = \"{secret}\";\n}}\n").into_bytes()
        }
        SecretRule::PrivateKeyBlock => format!("# deploy key\n{secret}").into_bytes(),
        _ => {
            format!("config:\n  endpoint: https://api.local\n  upstream: '{secret}'\n").into_bytes()
        }
    }
}

#[test]
fn m1_every_planted_secret_is_found_by_its_rule() {
    for (rule, secret) in planted() {
        let blob = in_context(rule, &secret);
        let f = scan(&blob).unwrap_or_else(|| panic!("{} not found", rule.id()));
        if rule != SecretRule::SecretAssignment {
            assert_eq!(f.rule, rule, "rule for {}", rule.id());
        }
        // Binary context: the secret between non-text bytes is still found.
        let mut bin = vec![0u8, 0xFF, 0x80, b'\n'];
        bin.extend_from_slice(secret.as_bytes());
        bin.extend_from_slice(&[0u8, 0xFE]);
        if rule != SecretRule::SecretAssignment {
            assert_eq!(
                scan(&bin).map(|f| f.rule),
                Some(rule),
                "binary {}",
                rule.id()
            );
        }
    }
}

#[test]
fn m1_assignment_forms_are_found() {
    let mut g = Gen(7);
    let v = g.from(ALNUM, 32);
    let hex = g.from(b"0123456789abcdef", 64);
    for text in [
        format!("API_KEY={v}\n"),
        format!("export GITHUB_TOKEN={v}\n"),
        format!("{{\"client_secret\": \"{v}\"}}"),
        format!("password := \"{v}\""),
        format!("auth_token => '{v}',"),
        format!("secret: {hex}\n"),
    ] {
        assert_eq!(
            scan(text.as_bytes()).map(|f| f.rule),
            Some(SecretRule::SecretAssignment),
            "{text}"
        );
    }
}

#[test]
fn m1_lookalikes_and_marked_fake_examples_are_admitted() {
    let dash5 = "-".repeat(5);
    let negatives: Vec<String> = vec![
        // AWS documentation example key id (clearly fake: ends in EXAMPLE).
        format!("{}IOSFODNN7EXAMPLE", ["AK", "IA"].concat()),
        // Placeholder GitHub token from docs.
        format!("{}{}", ["gh", "p_"].concat(), "x".repeat(36)),
        // Wrong length and prefix glued to a word.
        format!("{}abc123", ["gh", "p_"].concat()),
        format!(
            "my{}{}",
            ["gh", "p_"].concat(),
            "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        ),
        // Stripe test keys are not live keys.
        format!(
            "{}{}",
            ["sk_", "test_"].concat(),
            "4eC39HqLyjWDarjtT1zdp7dc"
        ),
        // A PEM header in prose with no key body, and a public key block.
        format!("{dash5}BEGIN RSA PRIVATE KEY{dash5}\n...\n{dash5}END RSA PRIVATE KEY{dash5}"),
        format!(
            "{dash5}BEGIN PUBLIC KEY{dash5}\n{}\n",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA".repeat(3)
        ),
        // Assignments that are not literal secrets.
        "let token = generate_token_v2(seed_1234567890abcdef);".into(),
        "password = \"${DB_PASSWORD_FROM_ENVIRONMENT_1}\"".into(),
        "pub token: String,\n    secret: [u8; 32],".into(),
        "api_key = \"your-api-key-goes-here-123\"".into(),
        "client_secret = \"EXAMPLE0123456789abcdefEXAMPLE\"".into(),
        "if token == expected_token_value_1234 {}".into(),
        "let tokens = Vec::<Token>::with_capacity(1024);".into(),
        // High-entropy values under names that are not secret-like.
        "digest = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"".into(),
        "commit: 2f06c45a1b2c3d4e5f60718293a4b5c6d7e8f901".into(),
        // Rust paths with `::`.
        "synapse_api::secret_scan::check_blobs(&blobs)?;".into(),
        // A short hex value named token.
        "token = \"deadbeef12345678\"".into(),
    ];
    for n in &negatives {
        assert_eq!(scan(n.as_bytes()), None, "false refusal: {n}");
    }
}

#[test]
fn m1_refusal_names_rule_and_never_echoes_secret_bytes() {
    for (rule, secret) in planted() {
        let blob = in_context(rule, &secret);
        let digest = BlobDigest::compute(&blob);
        let ok = BlobDigest::compute(b"clean");
        let err = check_blobs(&[(ok, b"clean".to_vec()), (digest, blob)]).unwrap_err();
        assert_eq!(err.code, RefusalCode::SecretDetected);
        let rendered = format!("{err} {err:?}");
        assert!(rendered.contains(&digest.to_string()));
        assert!(rendered.contains(&format!("v{SECRET_RULESET_VERSION}")));
        // No 8-byte window of the secret appears in any rendering of the refusal.
        let s = secret.as_bytes();
        for w in s.windows(8) {
            let w = String::from_utf8_lossy(w);
            if w.contains('-') || w.contains('\n') {
                continue; // PEM framing is not secret material.
            }
            assert!(!rendered.contains(&*w), "{} leaked into refusal", rule.id());
        }
    }
}

/// Inputs built to make naive or backtracking matchers blow up: every trigger byte repeated,
/// near-miss prefixes, and long runs that stop one byte short of a match.
fn adversarial(len: usize) -> Vec<Vec<u8>> {
    let dash5 = "-".repeat(5);
    let units: Vec<String> = vec![
        format!("{dash5}BEGIN RSA PRIVATE KEY{dash5}\n"),
        format!("{dash5}BEGIN "),
        "-".into(),
        ["AK", "IA"].concat(),
        ["gh", "p_"].concat(),
        ["github", "_pat_"].concat(),
        format!("{}1-", ["xo", "xb-"].concat()),
        ["sk-", "ant-"].concat(),
        "sk-".into(),
        "token=".into(),
        "password:".into(),
        "a=".into(),
        "=".into(),
        ":".into(),
        format!("secret_token = \"{}\"\n", "Ab1".repeat(50)),
        format!("api_key={}", "Z9".repeat(64)),
        "hooks.slack.com/services/".into(),
    ];
    let mut out: Vec<Vec<u8>> = units
        .iter()
        .map(|u| u.as_bytes().iter().copied().cycle().take(len).collect())
        .collect();
    out.push(vec![b'a'; len]);
    out.push(vec![0u8; len]);
    let mut g = Gen(42);
    out.push((0..len).map(|_| g.next() as u8).collect());
    out
}

#[test]
fn m1_adversarial_input_is_linear_in_time_and_steps() {
    const LEN: usize = 1 << 22; // 4 MiB per input
    const STEPS_PER_BYTE: u64 = 64;
    for input in adversarial(LEN) {
        let t = Instant::now();
        let (_, steps) = scan_with_steps(&input);
        let took = t.elapsed();
        assert!(
            steps <= STEPS_PER_BYTE * input.len() as u64,
            "{steps} steps for {} bytes",
            input.len()
        );
        // Generous wall-clock ceiling for an unoptimized test build.
        assert!(took < Duration::from_secs(10), "took {took:?}");
        // Doubling the input at most doubles the work (plus a constant).
        let half = &input[..LEN / 2];
        let (_, half_steps) = scan_with_steps(half);
        assert!(steps <= 2 * half_steps + 65_536, "{steps} vs {half_steps}");
    }
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        if name == "target" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        if p.is_dir() {
            source_files(&p, out);
        } else if matches!(
            p.extension().and_then(|x| x.to_str()),
            Some("rs" | "md" | "toml" | "sh" | "json")
        ) {
            out.push(p);
        }
    }
}

/// Real AIEN source without secrets: this repository's own crates, docs, and scripts. The
/// false-refusal count is printed and must be zero.
#[test]
fn m1_real_aien_source_is_admitted_with_zero_false_refusals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for d in ["crates", "docs", "scripts"] {
        source_files(&root.join(d), &mut files);
    }
    files.sort();
    assert!(files.len() > 50, "corpus too small: {}", files.len());
    let mut bytes = 0usize;
    let mut refused = Vec::new();
    let t = Instant::now();
    for f in &files {
        let data = std::fs::read(f).unwrap();
        bytes += data.len();
        if let Some(found) = scan(&data) {
            refused.push(format!(
                "{} ({} @ {})",
                f.display(),
                found.rule.id(),
                found.offset
            ));
        }
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "m1 corpus: {} files, {} bytes, {} false refusals, {:.6} s scan (debug build)",
        files.len(),
        bytes,
        refused.len(),
        secs
    );
    assert!(refused.is_empty(), "false refusals: {refused:#?}");
}

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "synapse-m1-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn open(label: &str) -> SynapseService {
    SynapseService::open(
        temp_dir(label),
        repo(),
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits {
            wal_prealloc_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap()
}

/// Envelope v1 `submit`: a blob with a secret is refused before any WAL write; a clean blob
/// in the same service is then admitted.
#[test]
fn m1_submit_refuses_secret_blob_before_any_wal_write() {
    let mut svc = open("submit");
    let auth = SigningKey::from_bytes(&[10; 32]);
    svc.register_authority(encode_did_key_ed25519(&auth.verifying_key().to_bytes()));
    let agent = SigningKey::from_bytes(&[20; 32]);
    let agent_did = encode_did_key_ed25519(&agent.verifying_key().to_bytes());
    let base = GitOid::compute_blob(b"base");
    svc.register_base_tree(
        base,
        vec![("README.md".into(), FileMode::Regular644, b"base".to_vec())],
    )
    .unwrap();
    let grant = AgentCapabilityGrant::issue(
        &auth,
        [1; 32],
        repo(),
        agent_did,
        vec![Capability::Read, Capability::Propose],
        1 << 20,
        100,
        60_000,
        10,
        100_000,
    );
    let request = |body: &[u8], n: u8| {
        let digest = BlobDigest::compute(body);
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo(),
            base_git_oid: base,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey([n; 32]),
            created_at_ms: 100,
            intent_summary: "edit config".into(),
            mutations: vec![PathMutation {
                path: "src/config.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: digest,
                    size_bytes: body.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(&agent);
        AuthenticatedRequest::sign_new(
            &agent,
            grant.clone(),
            repo(),
            Capability::Propose,
            [n; 32],
            100,
            0,
            SubmitChangesetPayload {
                envelope: env,
                blobs: vec![(digest, body.to_vec())],
            },
        )
        .unwrap()
    };
    let before = svc.store().committed_seq();
    for (i, (rule, secret)) in planted().into_iter().enumerate() {
        let body = in_context(rule, &secret);
        let err = svc.submit(&request(&body, 100 + i as u8), 100).unwrap_err();
        assert_eq!(err.code, RefusalCode::SecretDetected, "{}", rule.id());
        assert!(!err.message.contains(&secret));
        assert_eq!(svc.store().committed_seq(), before, "WAL advanced");
        assert!(svc
            .read_blob_bytes(BlobDigest::compute(&body), None)
            .is_err());
    }
    let clean = b"pub fn port() -> u16 { 8080 }\n";
    let out = svc.submit(&request(clean, 1), 100).unwrap();
    assert!(matches!(out, IngestOutcome::Committed { .. }));
    assert!(svc.store().committed_seq() > before);
}

/// Envelope v2 `submit_revision` under an F1 chain: the same refusal, no WAL write.
#[test]
fn m1_submit_revision_refuses_secret_blob_before_any_wal_write() {
    const NOW: u64 = 2_000;
    const C: ChangeId = ChangeId([0xC1; 16]);
    let mut svc = open("revision");
    let a = SigningKey::from_bytes(&[1; 32]);
    let o = SigningKey::from_bytes(&[2; 32]);
    svc.auth_mut().register_repo_authority(
        repo(),
        encode_did_key_ed25519(&a.verifying_key().to_bytes()),
    );
    let caveats = LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: 1_000,
            window_duration_ms: 60_000,
            storage_bytes: 1 << 30,
            footprint_paths: 1 << 20,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 1_000,
        expires_at_ms: 100_000,
    };
    let link = CapabilityLink::issue(
        &a,
        ROOT_PARENT,
        [0xA0; 32],
        repo(),
        o.verifying_key().to_bytes(),
        caveats,
    );
    let chain = CapabilityChain::new(vec![link]);
    svc.auth_mut().grant_link(&chain, WalSeq(0), NOW).unwrap();
    let base_oid = GitOid([0x0B; 20]);
    svc.register_base_tree(
        base_oid,
        vec![("README.md".into(), FileMode::Regular644, b"base".to_vec())],
    )
    .unwrap();
    let base = svc
        .tree_digest(TreeTarget::BaseGitCommit(base_oid), None)
        .unwrap();
    let mut submit = |body: &[u8], n: u8| {
        let content = RevisionContent {
            change_id: C,
            base_tree: base,
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                },
            }],
            intent_summary: "implement the task".into(),
        };
        let env = ChangesetEnvelopeV2::sign_new(&o, repo(), content, IdempotencyKey([n; 32]), NOW);
        let req = ChainedRequest::sign_new(
            &o,
            chain.clone(),
            repo(),
            Capability::Propose,
            RequestScope {
                paths: vec!["src/lib.rs".into()],
                reference: None,
                join_change: Some(C),
            },
            [n; 32],
            NOW,
            env.encode(),
        );
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        let before = svc.store().committed_seq();
        let r = svc.submit_revision(&req, &blobs, NOW);
        (r.map(|_| ()), before, svc.store().committed_seq())
    };
    let (rule, secret) = planted().swap_remove(5);
    let body = in_context(rule, &secret);
    let (r, before, after) = submit(&body, 7);
    let err = r.unwrap_err();
    assert_eq!(err.code, RefusalCode::SecretDetected);
    assert!(!err.message.contains(&secret));
    assert_eq!(before, after, "WAL advanced on a refused secret");
    let (r, before, after) = submit(b"pub fn ok() {}\n", 8);
    r.unwrap();
    assert!(after > before);
}
