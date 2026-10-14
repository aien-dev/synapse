//! Parity with the reference `crumb.c` (aien-architecture 29780e5), via the golden files
//! written by `scripts/crumb-parity.sh`. Each fixture `dot.crumb` stands for `.crumb`.
//!
//! The leaf entry must match `sniff` and `validate`; `nearest` and `inherited_invariants`
//! must match `explain`. Fixtures where the tools deliberately disagree (ADR 0004 sections
//! 2.2 and 2.3) are listed in [`DIVERGENCES`] and asserted field by field on both sides, so
//! a change in either tool fails a test instead of being skipped.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use synapse_crumb::json::JsonError;
use synapse_crumb::{
    crumb_path, CrumbContext, CrumbContextEntry, CrumbFile, Dialect, DirectoryCrumb, EntryStatus,
    InvalidReason, MAX_CRUMB_BYTES, ROOT_DIR,
};

const TARGETS: [&str; 16] = [
    ".",
    "d1",
    "d1/nested",
    "d1/nested/deeper",
    "d2",
    "d3",
    "badjson",
    "gap",
    "gap/inner",
    "unknown",
    "bom",
    "scalar",
    "latin1",
    "nuljunk",
    "dupkey",
    "surrogate",
];

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, base, out);
        } else {
            let rel = p.strip_prefix(base).unwrap().to_str().unwrap().to_string();
            let rel = match rel.strip_suffix("dot.crumb") {
                Some(prefix) => format!("{prefix}.crumb"),
                None => rel,
            };
            out.insert(rel, fs::read(&p).unwrap());
        }
    }
}

fn fixture_tree() -> BTreeMap<String, Vec<u8>> {
    let base = manifest().join("tests/fixtures/tree");
    let mut map = BTreeMap::new();
    walk(&base, &base, &mut map);
    map
}

fn context(tree: &BTreeMap<String, Vec<u8>>, target: &str) -> CrumbContext {
    CrumbContext::resolve(target, |p| {
        Ok(tree
            .get(p)
            .map_or(CrumbFile::Missing, |b| CrumbFile::Bytes(b.clone())))
    })
    .unwrap()
}

/// Lines of the golden block `### <kind> <target>`.
fn golden_block(kind: &str, target: &str) -> Vec<String> {
    let text = fs::read_to_string(manifest().join(format!("tests/golden/{kind}.txt"))).unwrap();
    let header = format!("### {kind} {target}");
    let mut lines = text.lines().skip_while(|l| *l != header);
    assert_eq!(
        lines.next(),
        Some(header.as_str()),
        "missing golden block {header}"
    );
    lines
        .take_while(|l| !l.starts_with("### "))
        .map(str::to_string)
        .collect()
}

/// The golden `validate` line about one directory's `.crumb`, if crumb.c printed one.
fn golden_validate_line(dir: &str) -> Option<String> {
    let text = fs::read_to_string(manifest().join("tests/golden/validate.txt")).unwrap();
    let f = abs_crumb(dir);
    text.lines()
        .find(|l| {
            (l.starts_with("INVALID ") || l.starts_with("LEGACY "))
                && (l.contains(&format!(" {f}:")) || l.contains(&format!(" {f} (")))
        })
        .map(str::to_string)
}

fn abs_crumb(dir: &str) -> String {
    if dir == ROOT_DIR {
        "<ROOT>/.crumb".to_string()
    } else {
        format!("<ROOT>/{dir}/.crumb")
    }
}

fn abs_dir(dir: &str) -> String {
    if dir == ROOT_DIR {
        "<ROOT>".to_string()
    } else {
        format!("<ROOT>/{dir}")
    }
}

/// A fixture where Synapse and crumb.c deliberately disagree (ADR 0004 section 2.3).
/// Every field is asserted, so drift on either side fails a test instead of being skipped.
struct Divergence {
    target: &'static str,
    /// The leaf status Synapse must report.
    synapse: fn(&EntryStatus) -> bool,
    /// crumb.c `sniff` lines after the `sniff <dir> as parity` header.
    sniff: &'static [&'static str],
    /// crumb.c `validate` line for the file, or `None` when crumb.c finds it valid.
    validate: Option<&'static str>,
    /// Directory crumb.c `explain` reports as NEAREST CRUMB.
    crumb_c_nearest: &'static str,
    /// Directory Synapse reports as nearest.
    synapse_nearest: &'static str,
}

const DIVERGENCES: [Divergence; 6] = [
    // crumb.c reads any JSON object; Synapse refuses an object of no known dialect.
    Divergence {
        target: "unknown",
        synapse: |s| *s == EntryStatus::Invalid(InvalidReason::UnknownJsonDialect),
        sniff: &[
            "  .crumb: unknown-object | JSON object with neither schema_version nor version.",
            "  invariant: unknown invariant",
        ],
        validate: Some(
            "INVALID <ROOT>/unknown/.crumb: needs schema_version \"1.0.0\", name, purpose",
        ),
        crumb_c_nearest: "unknown",
        synapse_nearest: ROOT_DIR,
    },
    // crumb.c sniff prints any parsed JSON value, even a top-level string.
    Divergence {
        target: "scalar",
        synapse: |s| *s == EntryStatus::Invalid(InvalidReason::UnrecognizedFormat),
        sniff: &["  .crumb: ? | (legacy format)"],
        validate: Some("INVALID <ROOT>/scalar/.crumb: not a JSON object"),
        crumb_c_nearest: ROOT_DIR,
        synapse_nearest: ROOT_DIR,
    },
    // crumb.c copies string bytes without checking UTF-8; Synapse refuses non-UTF-8.
    Divergence {
        target: "latin1",
        synapse: |s| *s == EntryStatus::Invalid(InvalidReason::NotUtf8),
        sniff: &[
            "  .crumb: latin1 | RFC-0001 document with one Latin-1 byte in an unprinted field.",
        ],
        validate: None,
        crumb_c_nearest: "latin1",
        synapse_nearest: ROOT_DIR,
    },
    // crumb.c parses a C string, so a NUL ends the document; Synapse refuses the trailing bytes.
    Divergence {
        target: "nuljunk",
        synapse: |s| {
            matches!(
                s,
                EntryStatus::Invalid(InvalidReason::Json(JsonError::Syntax { .. }))
            )
        },
        sniff: &["  .crumb: nuljunk | RFC-0001 document followed by a NUL byte and junk."],
        validate: None,
        crumb_c_nearest: "nuljunk",
        synapse_nearest: ROOT_DIR,
    },
    // crumb.c keeps the last value of a duplicated key; Synapse refuses duplicates.
    Divergence {
        target: "dupkey",
        synapse: |s| {
            matches!(
                s,
                EntryStatus::Invalid(InvalidReason::Json(JsonError::DuplicateKey { .. }))
            )
        },
        sniff: &["  .crumb: dupkey | second purpose"],
        validate: None,
        crumb_c_nearest: "dupkey",
        synapse_nearest: ROOT_DIR,
    },
    // crumb.c turns a lone UTF-16 surrogate escape into U+FFFD; Synapse refuses it.
    Divergence {
        target: "surrogate",
        synapse: |s| {
            matches!(
                s,
                EntryStatus::Invalid(InvalidReason::Json(JsonError::Syntax { .. }))
            )
        },
        sniff: &["  .crumb: surrogate | lone surrogate [\u{FFFD}] here"],
        validate: None,
        crumb_c_nearest: "surrogate",
        synapse_nearest: ROOT_DIR,
    },
];

fn divergence(target: &str) -> Option<&'static Divergence> {
    DIVERGENCES.iter().find(|d| d.target == target)
}

/// What crumb.c `sniff` prints for the directory's own `.crumb`, derived from the typed leaf,
/// or `None` when the Synapse status has no single crumb.c rendering (only allowed for
/// [`DIVERGENCES`]). crumb.c reads only JSON and only top-level string `name`/`purpose`:
/// D2 has neither (its `purpose` is an object), and D3 is not JSON.
fn sniff_lines(target: &str, leaf: &CrumbContextEntry) -> Option<Vec<String>> {
    let mut out = vec![format!("sniff {} as parity", abs_dir(target))];
    match &leaf.status {
        EntryStatus::Present(DirectoryCrumb::Rfc0001(c)) => {
            out.push(format!("  .crumb: {} | {}", c.name, c.purpose));
            out.extend(c.invariants.iter().map(|i| format!("  invariant: {i}")));
        }
        EntryStatus::Present(DirectoryCrumb::Atlas(_)) => {
            out.push("  .crumb: ? | (legacy format)".to_string())
        }
        EntryStatus::Present(DirectoryCrumb::YamlV1(_))
        | EntryStatus::Missing
        | EntryStatus::Invalid(InvalidReason::UnrecognizedFormat)
        | EntryStatus::Invalid(InvalidReason::Json(JsonError::Syntax { .. })) => {
            out.push("  no .crumb here".to_string())
        }
        _ => return None,
    }
    Some(out)
}

/// What crumb.c `validate` prints for one `.crumb`: `Some(None)` for nothing, `None` when
/// the Synapse status has no single crumb.c rendering (only allowed for [`DIVERGENCES`]).
fn validate_line(e: &CrumbContextEntry) -> Option<Option<String>> {
    let f = abs_crumb(&e.dir);
    Some(match &e.status {
        EntryStatus::Missing | EntryStatus::Present(DirectoryCrumb::Rfc0001(_)) => None,
        EntryStatus::Present(DirectoryCrumb::Atlas(_)) => {
            Some(format!("LEGACY  {f} (pre-RFC format, not validated)"))
        }
        EntryStatus::Present(DirectoryCrumb::YamlV1(_))
        | EntryStatus::Invalid(
            InvalidReason::UnrecognizedFormat
            | InvalidReason::Json(JsonError::Syntax { .. })
            | InvalidReason::NotJsonObject,
        ) => Some(format!("INVALID {f}: not a JSON object")),
        EntryStatus::Invalid(
            InvalidReason::UnknownJsonDialect
            | InvalidReason::UnsupportedSchemaVersion
            | InvalidReason::MissingField {
                dialect: Dialect::Rfc0001Json,
                ..
            },
        ) => Some(format!(
            "INVALID {f}: needs schema_version \"1.0.0\", name, purpose"
        )),
        _ => return None,
    })
}

/// crumb.c `explain` NEAREST CRUMB and INHERITED INVARIANTS, from the typed context, or
/// `None` when the nearest crumb has no crumb.c rendering (D3, asserted separately).
/// `export:` and `related:` lines are not modelled by Synapse and are dropped from both sides.
fn explain_lines(ctx: &CrumbContext) -> Option<Vec<String>> {
    let mut out = vec!["== NEAREST CRUMB ==".to_string()];
    match ctx.nearest() {
        None => out.push("  (no .crumb found at or above this path)".to_string()),
        Some(e) => {
            out.push(format!("  file: {}", abs_crumb(&e.dir)));
            let (name, layer, purpose, inv): (&str, &str, &str, &[String]) = match e.crumb() {
                Some(DirectoryCrumb::Rfc0001(c)) => (
                    &c.name,
                    c.layer.as_deref().unwrap_or(""),
                    &c.purpose,
                    &c.invariants,
                ),
                Some(DirectoryCrumb::Atlas(_)) => ("", "", "", &[]),
                _ => return None,
            };
            out.push(format!("  name: {name}"));
            out.push(format!("  layer: {layer}"));
            out.push(format!("  purpose: {purpose}"));
            if inv.is_empty() {
                out.push("  invariant: (none)".to_string());
            }
            out.extend(inv.iter().map(|i| format!("  invariant: {i}")));
        }
    }
    out.push("== INHERITED INVARIANTS ==".to_string());
    let inherited = ctx.inherited_invariants();
    if inherited.is_empty() {
        out.push("  (none)".to_string());
    }
    out.extend(
        inherited
            .iter()
            .map(|(d, i)| format!("  from {}: {i}", abs_crumb(d))),
    );
    Some(out)
}

fn without_unmodelled(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|l| !l.starts_with("  export: ") && !l.starts_with("  related: "))
        .collect()
}

#[test]
fn pinned_source_matches_script() {
    let pin = fs::read_to_string(manifest().join("tests/golden/PIN")).unwrap();
    assert!(pin.contains("commit 29780e56c9e6b9111d884e0d4b146737228c19f6"));
    assert!(pin.contains(
        "crumb.c sha256 ef0f6566fb838917a750eb898f66596b76aa15a53d7d61bedac03c4c963ee147"
    ));
}

#[test]
fn script_targets_match_test_targets() {
    let script = fs::read_to_string(manifest().join("../../scripts/crumb-parity.sh")).unwrap();
    let start = script.find("TARGETS=(").unwrap() + "TARGETS=(".len();
    let end = start + script[start..].find(')').unwrap();
    let listed: Vec<&str> = script[start..end].split_whitespace().collect();
    assert_eq!(listed, TARGETS);
}

#[test]
fn fixtures_stay_below_the_size_cap() {
    for (path, bytes) in fixture_tree() {
        assert!((bytes.len() as u64) < MAX_CRUMB_BYTES, "{path}");
    }
}

#[test]
fn leaf_dialects_are_as_designed() {
    let tree = fixture_tree();
    let leaf = |t: &str| context(&tree, t).leaf().clone();
    assert_eq!(leaf("d1").dialect(), Some(Dialect::Rfc0001Json));
    assert_eq!(leaf("d2").dialect(), Some(Dialect::AtlasJson));
    assert_eq!(leaf("d3").dialect(), Some(Dialect::YamlV1));
    assert_eq!(leaf("gap").status, EntryStatus::Missing);
    assert!(matches!(
        leaf("badjson").status,
        EntryStatus::Invalid(InvalidReason::Json(_))
    ));
    // A UTF-8 byte order mark is not JSON whitespace: refused by both tools.
    assert_eq!(
        leaf("bom").status,
        EntryStatus::Invalid(InvalidReason::UnrecognizedFormat)
    );
    for d in &DIVERGENCES {
        assert!((d.synapse)(&leaf(d.target).status), "{}", d.target);
    }
    match leaf("d2").crumb() {
        Some(DirectoryCrumb::Atlas(a)) => assert_eq!(
            a.purpose_statement.as_deref(),
            Some("Pre-RFC Atlas spark-crumbs directory.")
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn sniff_matches_crumb_c() {
    let tree = fixture_tree();
    for t in TARGETS {
        let ctx = context(&tree, t);
        let golden = golden_block("sniff", t);
        let mapped = sniff_lines(t, ctx.leaf());
        match divergence(t) {
            Some(d) => {
                assert_eq!(golden[1..], *d.sniff, "crumb.c sniff {t} drifted");
                assert!((d.synapse)(&ctx.leaf().status), "Synapse sniff {t} drifted");
                assert_ne!(mapped.as_ref(), Some(&golden), "{t} no longer diverges");
            }
            None => assert_eq!(
                mapped.unwrap_or_else(|| panic!("{t}: unmapped status outside DIVERGENCES")),
                golden,
                "sniff {t}"
            ),
        }
    }
}

#[test]
fn validate_matches_crumb_c() {
    let tree = fixture_tree();
    for t in TARGETS {
        let leaf = context(&tree, t).leaf().clone();
        let golden = golden_validate_line(t);
        let mapped = validate_line(&leaf);
        match divergence(t) {
            Some(d) => {
                assert_eq!(
                    golden.as_deref(),
                    d.validate,
                    "crumb.c validate {t} drifted"
                );
                assert!((d.synapse)(&leaf.status), "Synapse validate {t} drifted");
                // Synapse refuses every divergent fixture, so its own verdict is "invalid".
                assert!(leaf.crumb().is_none(), "{t}");
            }
            None => assert_eq!(
                mapped.unwrap_or_else(|| panic!("{t}: unmapped status outside DIVERGENCES")),
                golden,
                "validate {t}"
            ),
        }
    }

    let golden = fs::read_to_string(manifest().join("tests/golden/validate.txt")).unwrap();
    let present = TARGETS
        .iter()
        .filter(|t| tree.contains_key(&crumb_path(t)))
        .count();
    assert!(golden.contains(&format!(
        "{present} .crumb file(s), 0 directory(ies) with live local crumbs, INVALID found"
    )));
    assert!(golden.ends_with("exit 1\n"));
}

#[test]
fn explain_matches_crumb_c() {
    let tree = fixture_tree();
    for t in TARGETS {
        let ctx = context(&tree, t);
        let golden = without_unmodelled(golden_block("explain", t));
        if let Some(d) = divergence(t) {
            assert_eq!(
                golden[1],
                format!("  file: {}", abs_crumb(d.crumb_c_nearest)),
                "crumb.c explain {t} drifted"
            );
            assert_eq!(ctx.nearest().unwrap().dir, d.synapse_nearest, "{t}");
            if d.crumb_c_nearest == d.synapse_nearest {
                assert_eq!(explain_lines(&ctx).unwrap(), golden, "explain {t}");
            }
            continue;
        }
        match t {
            // Divergence: crumb.c cannot parse D3, so it falls back to the root crumb;
            // Synapse reports the typed D3 crumb as nearest.
            "d3" => {
                assert_eq!(golden[1], "  file: <ROOT>/.crumb");
                let n = ctx.nearest().unwrap();
                assert_eq!((n.dir.as_str(), n.dialect()), ("d3", Some(Dialect::YamlV1)));
                assert_eq!(explain_lines(&ctx), None);
                assert!(ctx.inherited_invariants().len() == 2);
            }
            _ => assert_eq!(explain_lines(&ctx).unwrap(), golden, "explain {t}"),
        }
    }
}

#[test]
fn chains_include_missing_intermediate_entries() {
    let tree = fixture_tree();
    let ctx = context(&tree, "gap/inner");
    let s: Vec<(&str, bool)> = ctx
        .entries()
        .iter()
        .map(|e| (e.dir.as_str(), e.status == EntryStatus::Missing))
        .collect();
    assert_eq!(s, [(".", false), ("gap", true), ("gap/inner", false)]);
    let deeper = context(&tree, "d1/nested/deeper");
    assert_eq!(deeper.entries().len(), 4);
    assert_eq!(deeper.nearest().unwrap().dir, "d1/nested");
}
