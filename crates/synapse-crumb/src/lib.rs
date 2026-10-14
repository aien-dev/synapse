//! Versioned, bounded reader for Directory Crumb (`.crumb`) context over Synapse virtual trees (ADR 0004).
//!
//! * Each known on-disk dialect parses into its own typed variant of [`DirectoryCrumb`];
//!   nothing is coerced between dialects and anything else is refused with an [`InvalidReason`].
//! * [`CrumbContext`] is the root-to-directory chain of `.crumb` entries for one snapshot,
//!   with missing and invalid entries reported, matching `crumb.c` `sniff`, `validate`, and
//!   `explain` (pinned at aien-architecture `29780e5`) except for the divergences listed in ADR 0004.
//! * [`CrumbContextDigest`] is a domain-separated SHA-256 over the whole chain.
//!
//! The crate performs no I/O of its own: the caller supplies the bytes for each `.crumb`
//! path (see `SynapseService::crumb_context` in `synapse-api`).

pub mod json;
pub mod yaml;

use json::{JsonError, JsonValue};
use sha2::{Digest, Sha256};
use std::fmt;
use synapse_core::{
    validate_repo_relative_path, BlobDigest, RefusalCode, SynapseError, SynapseResult,
};
use yaml::{YamlCrumbV1, YamlError};

/// File name of a Directory Crumb.
pub const CRUMB_FILE_NAME: &str = ".crumb";

/// Largest `.crumb` document accepted, in bytes. `crumb.c` has no cap; this is a deliberate divergence.
pub const MAX_CRUMB_BYTES: u64 = 64 * 1024;

/// Largest number of directories in one chain (root included).
pub const MAX_CHAIN_LEN: usize = 256;

/// `schema_version` required by RFC-0001 (D1).
pub const RFC0001_SCHEMA_VERSION: &str = "1.0.0";

/// Domain separation tag for [`CrumbContextDigest`].
pub const DOMAIN_CRUMB_CONTEXT_V1: &[u8] = b"SYNAPSE_CRUMB_CONTEXT_V1\0";

/// Repository-relative name of the repository root directory.
pub const ROOT_DIR: &str = ".";

/// A recognised Directory Crumb dialect (ADR 0004 section 1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dialect {
    /// D1: RFC-0001 JSON, `schema_version` `"1.0.0"`.
    Rfc0001Json,
    /// D2: pre-RFC Atlas / `spark-crumbs` `DirCrumb` JSON (`version`, no `schema_version`).
    AtlasJson,
    /// D3: YAML-like `schema: "crumb/v1"`.
    YamlV1,
}

impl Dialect {
    /// Stable byte used in [`CrumbContextDigest`]; 0 is reserved for "no dialect".
    pub fn tag_byte(self) -> u8 {
        match self {
            Self::Rfc0001Json => 1,
            Self::AtlasJson => 2,
            Self::YamlV1 => 3,
        }
    }
}

/// D1 document: the fields Synapse surfaces. The full bytes are pinned by the entry's `BlobDigest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rfc0001Crumb {
    pub name: String,
    pub purpose: String,
    pub layer: Option<String>,
    /// Textual guidance; enforced by nothing until made a deterministic check.
    pub invariants: Vec<String>,
}

/// D2 document, following `spark-crumbs` `DirCrumb` (aien-sovereign-core `d01201b`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtlasCrumb {
    pub version: u32,
    pub dir_path: String,
    pub dir_name: String,
    pub description: String,
    /// `purpose.statement` when a `purpose` object is present.
    pub purpose_statement: Option<String>,
}

/// A successfully parsed Directory Crumb, one variant per dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryCrumb {
    Rfc0001(Rfc0001Crumb),
    Atlas(AtlasCrumb),
    YamlV1(YamlCrumbV1),
}

impl DirectoryCrumb {
    pub fn dialect(&self) -> Dialect {
        match self {
            Self::Rfc0001(_) => Dialect::Rfc0001Json,
            Self::Atlas(_) => Dialect::AtlasJson,
            Self::YamlV1(_) => Dialect::YamlV1,
        }
    }

    /// RFC-0001 invariants; other dialects define none.
    pub fn invariants(&self) -> &[String] {
        match self {
            Self::Rfc0001(c) => &c.invariants,
            _ => &[],
        }
    }
}

/// Why a `.crumb` file was refused. Every variant has a stable [`InvalidReason::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidReason {
    /// Larger than [`MAX_CRUMB_BYTES`]; not read.
    TooLarge {
        size: u64,
    },
    /// The tree entry is a symlink, not a regular file.
    NotRegularFile,
    NotUtf8,
    /// Neither JSON (`{` or `[` first) nor a D3 `schema:` document.
    UnrecognizedFormat,
    Json(JsonError),
    /// Valid JSON whose top level is not an object.
    NotJsonObject,
    /// A JSON object with neither `schema_version` nor `version`.
    UnknownJsonDialect,
    /// D1 `schema_version` is not the string `"1.0.0"`.
    UnsupportedSchemaVersion,
    MissingField {
        dialect: Dialect,
        field: &'static str,
    },
    WrongFieldType {
        dialect: Dialect,
        field: &'static str,
    },
    Yaml(YamlError),
}

impl InvalidReason {
    /// Stable code bound into [`CrumbContextDigest`].
    pub fn code(&self) -> u16 {
        match self {
            Self::TooLarge { .. } => 1,
            Self::NotRegularFile => 2,
            Self::NotUtf8 => 3,
            Self::UnrecognizedFormat => 4,
            Self::Json(JsonError::Syntax { .. }) => 5,
            Self::Json(JsonError::TooDeep) => 6,
            Self::Json(JsonError::DuplicateKey { .. }) => 7,
            Self::NotJsonObject => 8,
            Self::UnknownJsonDialect => 9,
            Self::UnsupportedSchemaVersion => 10,
            Self::MissingField { .. } => 11,
            Self::WrongFieldType { .. } => 12,
            Self::Yaml(YamlError::Syntax { .. }) => 13,
            Self::Yaml(YamlError::DuplicateKey { .. }) => 14,
            Self::Yaml(YamlError::ComponentIncomplete { .. }) => 15,
            Self::Yaml(YamlError::UnsupportedSchema) => 16,
        }
    }

    /// The dialect the file claimed, when it got far enough to claim one.
    pub fn claimed_dialect(&self) -> Option<Dialect> {
        match self {
            Self::UnsupportedSchemaVersion => Some(Dialect::Rfc0001Json),
            Self::MissingField { dialect, .. } | Self::WrongFieldType { dialect, .. } => {
                Some(*dialect)
            }
            Self::Yaml(_) => Some(Dialect::YamlV1),
            _ => None,
        }
    }
}

/// Parse one `.crumb` document into its typed dialect, or say why not.
pub fn parse_crumb(bytes: &[u8]) -> Result<DirectoryCrumb, InvalidReason> {
    if bytes.len() as u64 > MAX_CRUMB_BYTES {
        return Err(InvalidReason::TooLarge {
            size: bytes.len() as u64,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InvalidReason::NotUtf8)?;
    let first = text
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .bytes()
        .next();
    if matches!(first, Some(b'{' | b'[')) {
        let v = json::parse(text).map_err(InvalidReason::Json)?;
        if !matches!(v, JsonValue::Object(_)) {
            return Err(InvalidReason::NotJsonObject);
        }
        if v.get("schema_version").is_some() {
            return parse_rfc0001(&v).map(DirectoryCrumb::Rfc0001);
        }
        if v.get("version").is_some() {
            return parse_atlas(&v).map(DirectoryCrumb::Atlas);
        }
        return Err(InvalidReason::UnknownJsonDialect);
    }
    if yaml::looks_like_yaml_v1(text) {
        return yaml::parse(text)
            .map(DirectoryCrumb::YamlV1)
            .map_err(InvalidReason::Yaml);
    }
    Err(InvalidReason::UnrecognizedFormat)
}

fn req_str(v: &JsonValue, d: Dialect, field: &'static str) -> Result<String, InvalidReason> {
    match v.get(field) {
        None => Err(InvalidReason::MissingField { dialect: d, field }),
        Some(JsonValue::String(s)) => Ok(s.clone()),
        Some(_) => Err(InvalidReason::WrongFieldType { dialect: d, field }),
    }
}

fn opt_str(
    v: &JsonValue,
    d: Dialect,
    field: &'static str,
) -> Result<Option<String>, InvalidReason> {
    match v.get(field) {
        None => Ok(None),
        Some(_) => req_str(v, d, field).map(Some),
    }
}

fn parse_rfc0001(v: &JsonValue) -> Result<Rfc0001Crumb, InvalidReason> {
    const D: Dialect = Dialect::Rfc0001Json;
    if v.get("schema_version").and_then(JsonValue::as_str) != Some(RFC0001_SCHEMA_VERSION) {
        return Err(InvalidReason::UnsupportedSchemaVersion);
    }
    let name = req_str(v, D, "name")?;
    let purpose = req_str(v, D, "purpose")?;
    let layer = opt_str(v, D, "layer")?;
    let invariants = match v.get("invariants") {
        None => Vec::new(),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|i| i.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or(InvalidReason::WrongFieldType {
                dialect: D,
                field: "invariants",
            })?,
        Some(_) => {
            return Err(InvalidReason::WrongFieldType {
                dialect: D,
                field: "invariants",
            })
        }
    };
    Ok(Rfc0001Crumb {
        name,
        purpose,
        layer,
        invariants,
    })
}

/// D2 checks mirror the serde shape of `spark-crumbs` `DirCrumb`: required `version` (u32),
/// `dir_path`, `dir_name`, `description`; `purpose` absent, null, or an object with a string
/// `statement`; `above` absent, null, a string, or an object of strings `path`, `canonical`,
/// `name`, `role`; required arrays `below` (objects with strings `name`, `item_type`, `role`),
/// `history`, and `whispers` (objects; their inner fields are not checked).
fn parse_atlas(v: &JsonValue) -> Result<AtlasCrumb, InvalidReason> {
    const D: Dialect = Dialect::AtlasJson;
    let wrong = |field| InvalidReason::WrongFieldType { dialect: D, field };
    let version = match v.get("version") {
        Some(JsonValue::Number(n)) => n.parse::<u32>().map_err(|_| wrong("version"))?,
        _ => return Err(wrong("version")),
    };
    let dir_path = req_str(v, D, "dir_path")?;
    let dir_name = req_str(v, D, "dir_name")?;
    let description = req_str(v, D, "description")?;
    let purpose_statement = match v.get("purpose") {
        None | Some(JsonValue::Null) => None,
        Some(p @ JsonValue::Object(_)) => {
            Some(req_str(p, D, "statement").map_err(|e| match e {
                InvalidReason::MissingField { .. } => InvalidReason::MissingField {
                    dialect: D,
                    field: "purpose.statement",
                },
                _ => wrong("purpose.statement"),
            })?)
        }
        Some(_) => return Err(wrong("purpose")),
    };
    match v.get("above") {
        None | Some(JsonValue::Null) | Some(JsonValue::String(_)) => {}
        Some(a @ JsonValue::Object(_)) => {
            for f in ["path", "canonical", "name", "role"] {
                if a.get(f).and_then(JsonValue::as_str).is_none() {
                    return Err(wrong("above"));
                }
            }
        }
        Some(_) => return Err(wrong("above")),
    }
    for field in ["below", "history", "whispers"] {
        match v.get(field) {
            None => return Err(InvalidReason::MissingField { dialect: D, field }),
            Some(JsonValue::Array(items)) => {
                for item in items {
                    if !matches!(item, JsonValue::Object(_)) {
                        return Err(wrong(field));
                    }
                    if field == "below"
                        && ["name", "item_type", "role"]
                            .iter()
                            .any(|f| item.get(f).and_then(JsonValue::as_str).is_none())
                    {
                        return Err(wrong(field));
                    }
                }
            }
            Some(_) => return Err(wrong(field)),
        }
    }
    Ok(AtlasCrumb {
        version,
        dir_path,
        dir_name,
        description,
        purpose_statement,
    })
}

/// What a snapshot holds at one `.crumb` path, as supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrumbFile {
    /// No file at this path.
    Missing,
    /// A symlink entry; its target is not followed.
    NotRegularFile { blob_digest: BlobDigest },
    /// A file larger than [`MAX_CRUMB_BYTES`]; its bytes were not read.
    Oversized { blob_digest: BlobDigest, size: u64 },
    /// The file's bytes.
    Bytes(Vec<u8>),
}

/// Status of one directory's `.crumb` in a [`CrumbContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    Present(DirectoryCrumb),
    Missing,
    Invalid(InvalidReason),
}

impl EntryStatus {
    fn tag_byte(&self) -> u8 {
        match self {
            Self::Missing => 0,
            Self::Present(_) => 1,
            Self::Invalid(_) => 2,
        }
    }
}

/// One directory of a [`CrumbContext`] chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrumbContextEntry {
    /// Repository-relative directory, [`ROOT_DIR`] for the root.
    pub dir: String,
    pub status: EntryStatus,
    /// Digest of the `.crumb` bytes when a file exists (also for invalid files).
    pub blob_digest: Option<BlobDigest>,
}

impl CrumbContextEntry {
    /// Parsed dialect, or the dialect an invalid file claimed.
    pub fn dialect(&self) -> Option<Dialect> {
        match &self.status {
            EntryStatus::Present(c) => Some(c.dialect()),
            EntryStatus::Invalid(r) => r.claimed_dialect(),
            EntryStatus::Missing => None,
        }
    }

    pub fn crumb(&self) -> Option<&DirectoryCrumb> {
        match &self.status {
            EntryStatus::Present(c) => Some(c),
            _ => None,
        }
    }
}

/// Repository-relative path of the `.crumb` file in `dir`.
pub fn crumb_path(dir: &str) -> String {
    if dir == ROOT_DIR {
        CRUMB_FILE_NAME.to_string()
    } else {
        format!("{dir}/{CRUMB_FILE_NAME}")
    }
}

/// The Directory Crumb context of one directory in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrumbContext {
    target_dir: String,
    /// Root first, `target_dir` last.
    entries: Vec<CrumbContextEntry>,
}

impl CrumbContext {
    /// Build the chain for `target_dir` (`"."` or a clean repository-relative directory),
    /// asking `fetch` for each `.crumb` path from the root down.
    pub fn resolve(
        target_dir: &str,
        mut fetch: impl FnMut(&str) -> SynapseResult<CrumbFile>,
    ) -> SynapseResult<Self> {
        let mut dirs = vec![ROOT_DIR.to_string()];
        if target_dir != ROOT_DIR {
            validate_repo_relative_path(target_dir)?;
            let mut acc = String::new();
            for seg in target_dir.split('/') {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(seg);
                dirs.push(acc.clone());
            }
        }
        if dirs.len() > MAX_CHAIN_LEN {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("directory chain longer than {MAX_CHAIN_LEN}: {target_dir}"),
            ));
        }
        let mut entries = Vec::with_capacity(dirs.len());
        for dir in dirs {
            let (status, blob_digest) = match fetch(&crumb_path(&dir))? {
                CrumbFile::Missing => (EntryStatus::Missing, None),
                CrumbFile::NotRegularFile { blob_digest } => (
                    EntryStatus::Invalid(InvalidReason::NotRegularFile),
                    Some(blob_digest),
                ),
                CrumbFile::Oversized { blob_digest, size } => (
                    EntryStatus::Invalid(InvalidReason::TooLarge { size }),
                    Some(blob_digest),
                ),
                CrumbFile::Bytes(bytes) => {
                    let status = match parse_crumb(&bytes) {
                        Ok(c) => EntryStatus::Present(c),
                        Err(r) => EntryStatus::Invalid(r),
                    };
                    (status, Some(BlobDigest::compute(&bytes)))
                }
            };
            entries.push(CrumbContextEntry {
                dir,
                status,
                blob_digest,
            });
        }
        Ok(Self {
            target_dir: target_dir.to_string(),
            entries,
        })
    }

    pub fn target_dir(&self) -> &str {
        &self.target_dir
    }

    /// Root first, target directory last.
    pub fn entries(&self) -> &[CrumbContextEntry] {
        &self.entries
    }

    /// The target directory's own entry (what `crumb sniff` and `crumb validate` report).
    pub fn leaf(&self) -> &CrumbContextEntry {
        // `resolve` always pushes the root, so the chain is never empty.
        &self.entries[self.entries.len() - 1]
    }

    /// Nearest present crumb at or above the target (`crumb explain` "NEAREST CRUMB").
    pub fn nearest(&self) -> Option<&CrumbContextEntry> {
        self.entries
            .iter()
            .rev()
            .find(|e| matches!(e.status, EntryStatus::Present(_)))
    }

    /// Invariants of present crumbs strictly above [`Self::nearest`], closest ancestor first,
    /// each with its directory (`crumb explain` "INHERITED INVARIANTS").
    pub fn inherited_invariants(&self) -> Vec<(&str, &str)> {
        let Some(pos) = self
            .entries
            .iter()
            .rposition(|e| matches!(e.status, EntryStatus::Present(_)))
        else {
            return Vec::new();
        };
        self.entries[..pos]
            .iter()
            .rev()
            .filter_map(|e| e.crumb().map(|c| (e.dir.as_str(), c)))
            .flat_map(|(d, c)| c.invariants().iter().map(move |i| (d, i.as_str())))
            .collect()
    }

    /// Domain-separated digest of the whole chain, missing and invalid entries included.
    pub fn digest(&self) -> CrumbContextDigest {
        fn put(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        let mut h = Sha256::new();
        h.update(DOMAIN_CRUMB_CONTEXT_V1);
        put(&mut h, self.target_dir.as_bytes());
        h.update((self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            put(&mut h, e.dir.as_bytes());
            h.update([
                e.dialect().map_or(0, Dialect::tag_byte),
                e.status.tag_byte(),
            ]);
            let reason = match &e.status {
                EntryStatus::Invalid(r) => r.code(),
                _ => 0,
            };
            h.update(reason.to_le_bytes());
            match e.blob_digest {
                Some(d) => {
                    h.update([1]);
                    h.update(d.0);
                }
                None => h.update([0]),
            }
        }
        CrumbContextDigest(h.finalize().into())
    }
}

/// 32-byte domain-separated SHA-256 digest (`"SYNAPSE_CRUMB_CONTEXT_V1\0"`) of a [`CrumbContext`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CrumbContextDigest(pub [u8; 32]);

impl CrumbContextDigest {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CrumbContextDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CrumbContextDigest({})", self.to_hex())
    }
}

impl fmt::Display for CrumbContextDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const D1: &str =
        r#"{"schema_version":"1.0.0","name":"n","purpose":"p","invariants":["i1","i2"]}"#;

    fn ctx(files: &[(&str, &str)], dir: &str) -> CrumbContext {
        let map: BTreeMap<String, Vec<u8>> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect();
        CrumbContext::resolve(dir, |p| {
            Ok(map
                .get(p)
                .map_or(CrumbFile::Missing, |b| CrumbFile::Bytes(b.clone())))
        })
        .unwrap()
    }

    #[test]
    fn classifies_each_dialect_without_coercion() {
        assert!(matches!(
            parse_crumb(D1.as_bytes()),
            Ok(DirectoryCrumb::Rfc0001(_))
        ));
        let d2 = r#"{"version":1,"dir_path":"/x","dir_name":"x","description":"d","purpose":{"statement":"s"},"above":null,"below":[],"history":[],"whispers":[]}"#;
        match parse_crumb(d2.as_bytes()) {
            Ok(DirectoryCrumb::Atlas(a)) => assert_eq!(a.purpose_statement.as_deref(), Some("s")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_crumb(b"schema: \"crumb/v1\"\n"),
            Ok(DirectoryCrumb::YamlV1(_))
        ));
    }

    #[test]
    fn refuses_with_typed_reasons() {
        let cases: Vec<(&[u8], InvalidReason)> = vec![
            (b"[1]", InvalidReason::NotJsonObject),
            (b"{\"name\":\"x\"}", InvalidReason::UnknownJsonDialect),
            (
                b"{\"schema_version\":\"2.0.0\",\"name\":\"n\",\"purpose\":\"p\"}",
                InvalidReason::UnsupportedSchemaVersion,
            ),
            (
                b"{\"schema_version\":\"1.0.0\",\"name\":\"n\"}",
                InvalidReason::MissingField {
                    dialect: Dialect::Rfc0001Json,
                    field: "purpose",
                },
            ),
            (
                b"{\"schema_version\":\"1.0.0\",\"name\":\"n\",\"purpose\":\"p\",\"invariants\":\"x\"}",
                InvalidReason::WrongFieldType {
                    dialect: Dialect::Rfc0001Json,
                    field: "invariants",
                },
            ),
            (
                b"{\"version\":\"1\",\"dir_path\":\"a\"}",
                InvalidReason::WrongFieldType {
                    dialect: Dialect::AtlasJson,
                    field: "version",
                },
            ),
            (
                b"{\"version\":1,\"dir_path\":\"a\",\"dir_name\":\"a\",\"description\":\"d\",\"below\":[]}",
                InvalidReason::MissingField {
                    dialect: Dialect::AtlasJson,
                    field: "history",
                },
            ),
            (b"\xff\xfe", InvalidReason::NotUtf8),
            (b"name: x\n", InvalidReason::UnrecognizedFormat),
            (b"", InvalidReason::UnrecognizedFormat),
            (
                b"{\"a\":1,\"a\":2}",
                InvalidReason::Json(JsonError::DuplicateKey { offset: 7 }),
            ),
        ];
        for (doc, want) in cases {
            assert_eq!(
                parse_crumb(doc),
                Err(want),
                "{:?}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    /// Deliberate divergence from crumb.c (which reads any size): a document one byte over
    /// the cap is refused before parsing, even when it is otherwise a valid D1 crumb.
    #[test]
    fn size_cap_is_enforced_where_crumb_c_has_none() {
        let pad = MAX_CRUMB_BYTES as usize - D1.len();
        let at_cap = format!("{}{}", D1, " ".repeat(pad));
        assert_eq!(at_cap.len() as u64, MAX_CRUMB_BYTES);
        assert!(parse_crumb(at_cap.as_bytes()).is_ok());
        let over = format!("{at_cap} ");
        assert_eq!(
            parse_crumb(over.as_bytes()),
            Err(InvalidReason::TooLarge {
                size: MAX_CRUMB_BYTES + 1
            })
        );
    }

    #[test]
    fn chain_nearest_and_inherited_follow_explain() {
        let root = r#"{"schema_version":"1.0.0","name":"r","purpose":"p","invariants":["root-a"]}"#;
        let c = ctx(&[(".crumb", root), ("a/.crumb", D1)], "a/b/c");
        let dirs: Vec<&str> = c.entries().iter().map(|e| e.dir.as_str()).collect();
        assert_eq!(dirs, [".", "a", "a/b", "a/b/c"]);
        assert_eq!(c.leaf().status, EntryStatus::Missing);
        assert_eq!(c.nearest().unwrap().dir, "a");
        assert_eq!(c.inherited_invariants(), vec![(".", "root-a")]);

        let root_only = ctx(&[(".crumb", root)], ".");
        assert_eq!(root_only.entries().len(), 1);
        assert!(root_only.inherited_invariants().is_empty());

        let none = ctx(&[], "x");
        assert!(none.nearest().is_none());
    }

    #[test]
    fn invalid_entries_are_reported_and_skipped_for_nearest() {
        let c = ctx(&[(".crumb", D1), ("a/.crumb", "{not json")], "a");
        assert!(matches!(
            c.leaf().status,
            EntryStatus::Invalid(InvalidReason::Json(_))
        ));
        assert!(c.leaf().blob_digest.is_some());
        assert_eq!(c.nearest().unwrap().dir, ".");
    }

    #[test]
    fn digest_covers_missing_invalid_and_bytes() {
        let base = ctx(&[(".crumb", D1)], "a").digest();
        assert_eq!(base, ctx(&[(".crumb", D1)], "a").digest());
        // A different target directory changes the digest even with identical crumbs.
        assert_ne!(base, ctx(&[(".crumb", D1)], ".").digest());
        // Missing vs invalid at the same directory.
        assert_ne!(
            base,
            ctx(&[(".crumb", D1), ("a/.crumb", "{")], "a").digest()
        );
        // Different invalid bytes with the same reason code.
        assert_ne!(
            ctx(&[("a/.crumb", "{")], "a").digest(),
            ctx(&[("a/.crumb", "{x")], "a").digest()
        );
        // Not a BlobDigest of anything obvious: the domain tag separates it.
        assert_ne!(base.0, BlobDigest::compute(D1.as_bytes()).0);
    }

    #[test]
    fn oversized_and_symlink_entries_are_invalid_with_digest() {
        let d = BlobDigest::compute(b"x");
        let c = CrumbContext::resolve(".", |_| {
            Ok(CrumbFile::Oversized {
                blob_digest: d,
                size: MAX_CRUMB_BYTES + 1,
            })
        })
        .unwrap();
        assert_eq!(
            c.leaf().status,
            EntryStatus::Invalid(InvalidReason::TooLarge {
                size: MAX_CRUMB_BYTES + 1
            })
        );
        assert_eq!(c.leaf().blob_digest, Some(d));
        let s = CrumbContext::resolve(".", |_| Ok(CrumbFile::NotRegularFile { blob_digest: d }))
            .unwrap();
        assert_eq!(
            s.leaf().status,
            EntryStatus::Invalid(InvalidReason::NotRegularFile)
        );
    }

    #[test]
    fn refuses_bad_target_paths() {
        for bad in ["", "/a", "a/", "a/../b", "a/.git"] {
            let r = CrumbContext::resolve(bad, |_| Ok(CrumbFile::Missing));
            assert_eq!(r.unwrap_err().code, RefusalCode::PathInvalid, "{bad:?}");
        }
        let deep = vec!["d"; MAX_CHAIN_LEN].join("/");
        assert!(CrumbContext::resolve(&deep, |_| Ok(CrumbFile::Missing)).is_err());
    }
}
