//! The repository's own root `.crumb` is RFC-0001 JSON (D1), so the reference `crumb.c`
//! reads it too (ADR 0004 section 1.2: `crumb.c` cannot read the D3 dialect).

use std::fs;
use std::path::PathBuf;
use synapse_crumb::{parse_crumb, Dialect, DirectoryCrumb};

#[test]
fn repository_root_crumb_is_rfc0001() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.crumb");
    let bytes = fs::read(&path).expect("repository root .crumb exists");
    let crumb = parse_crumb(&bytes).expect("repository root .crumb parses");
    assert_eq!(crumb.dialect(), Dialect::Rfc0001Json);
    let DirectoryCrumb::Rfc0001(c) = crumb else {
        panic!("repository root .crumb is not D1");
    };
    assert_eq!(c.name, "synapse");
    assert_eq!(c.layer.as_deref(), Some("root"));
    assert!(!c.purpose.is_empty());
}
