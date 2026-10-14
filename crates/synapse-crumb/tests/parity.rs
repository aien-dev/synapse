//! Parity with the reference `crumb.c` (aien-architecture 29780e5), via the golden files
//! written by `scripts/crumb-parity.sh`. Each fixture `dot.crumb` stands for `.crumb`.
//!
//! The leaf entry must match `sniff` and `validate`; `nearest` and `inherited_invariants`
//! must match `explain`. The two divergences recorded in ADR 0004 section 2.3 are asserted
//! explicitly rather than skipped.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use synapse_crumb::{
    crumb_path, CrumbContext, CrumbContextEntry, CrumbFile, Dialect, DirectoryCrumb, EntryStatus,
    InvalidReason, MAX_CRUMB_BYTES, ROOT_DIR,
};

const TARGETS: [&str; 10] = [
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

/// What crumb.c `sniff` prints for the directory's own `.crumb`, derived from the typed leaf.
/// crumb.c reads only JSON and only top-level string `name`/`purpose`: D2 has neither
/// (its `purpose` is an object), and D3 is not JSON.
fn sniff_lines(target: &str, leaf: &CrumbContextEntry) -> Vec<String> {
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
        | EntryStatus::Invalid(InvalidReason::Json(_)) => out.push("  no .crumb here".to_string()),
        other => panic!("no crumb.c sniff mapping for {other:?}"),
    }
    out
}

/// What crumb.c `validate` prints for one `.crumb`, if anything.
fn validate_line(e: &CrumbContextEntry) -> Option<String> {
    let f = abs_crumb(&e.dir);
    match &e.status {
        EntryStatus::Missing | EntryStatus::Present(DirectoryCrumb::Rfc0001(_)) => None,
        EntryStatus::Present(DirectoryCrumb::Atlas(_)) => {
            Some(format!("LEGACY  {f} (pre-RFC format, not validated)"))
        }
        EntryStatus::Present(DirectoryCrumb::YamlV1(_))
        | EntryStatus::Invalid(InvalidReason::Json(_) | InvalidReason::NotJsonObject) => {
            Some(format!("INVALID {f}: not a JSON object"))
        }
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
        other => panic!("no crumb.c validate mapping for {other:?}"),
    }
}

/// crumb.c `explain` NEAREST CRUMB and INHERITED INVARIANTS, from the typed context.
/// `export:` and `related:` lines are not modelled by Synapse and are dropped from both sides.
fn explain_lines(ctx: &CrumbContext) -> Vec<String> {
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
                other => panic!("no crumb.c explain mapping for {other:?}"),
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
    out
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
    assert_eq!(
        leaf("unknown").status,
        EntryStatus::Invalid(InvalidReason::UnknownJsonDialect)
    );
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
        if t == "unknown" {
            // Divergence: crumb.c sniff prints any JSON object's top-level name/purpose.
            assert_eq!(
                golden_block("sniff", t)[1],
                "  .crumb: unknown-object | JSON object with neither schema_version nor version."
            );
            assert_eq!(
                ctx.leaf().status,
                EntryStatus::Invalid(InvalidReason::UnknownJsonDialect)
            );
            continue;
        }
        assert_eq!(
            sniff_lines(t, ctx.leaf()),
            golden_block("sniff", t),
            "sniff {t}"
        );
    }
}

#[test]
fn validate_matches_crumb_c() {
    let tree = fixture_tree();
    let golden = fs::read_to_string(manifest().join("tests/golden/validate.txt")).unwrap();
    let mut want: Vec<&str> = golden
        .lines()
        .filter(|l| l.starts_with("INVALID ") || l.starts_with("LEGACY "))
        .collect();
    want.sort();
    let mut got: Vec<String> = TARGETS
        .iter()
        .filter_map(|t| validate_line(context(&tree, t).leaf()))
        .collect();
    got.sort();
    assert_eq!(got, want);

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
        match t {
            // Divergence: crumb.c cannot parse D3, so it falls back to the root crumb;
            // Synapse reports the typed D3 crumb as nearest.
            "d3" => {
                assert_eq!(golden[1], "  file: <ROOT>/.crumb");
                let n = ctx.nearest().unwrap();
                assert_eq!((n.dir.as_str(), n.dialect()), ("d3", Some(Dialect::YamlV1)));
                assert!(ctx.inherited_invariants().len() == 2);
            }
            // Divergence: crumb.c treats any JSON object as nearest; Synapse refuses the
            // unknown object and falls back to the root crumb.
            "unknown" => {
                assert_eq!(golden[1], "  file: <ROOT>/unknown/.crumb");
                assert_eq!(ctx.nearest().unwrap().dir, ROOT_DIR);
                assert!(ctx.inherited_invariants().is_empty());
            }
            _ => assert_eq!(explain_lines(&ctx), golden, "explain {t}"),
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
