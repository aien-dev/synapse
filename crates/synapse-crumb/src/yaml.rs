//! Strict line reader for the D3 YAML-like `schema: "crumb/v1"` dialect.
//!
//! This is not a YAML parser. It accepts exactly the shape found in the
//! Synapse repository root `.crumb` (the only known instance; no writer tool is
//! known): top-level `key: "string"` lines and one `components:` list whose
//! items carry exactly `name`, `path`, and `role` as quoted strings. Blank lines
//! and `#` comment lines at column 0 are allowed. Everything else is refused.

use std::collections::BTreeMap;

/// Required value of the `schema` key for this dialect.
pub const YAML_V1_SCHEMA: &str = "crumb/v1";

/// One entry of the `components:` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlComponent {
    pub name: String,
    pub path: String,
    pub role: String,
}

/// A parsed D3 document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlCrumbV1 {
    /// Top-level scalar keys other than `schema`, in key order.
    pub fields: BTreeMap<String, String>,
    pub components: Vec<YamlComponent>,
}

impl YamlCrumbV1 {
    pub fn summary(&self) -> Option<&str> {
        self.fields.get("summary").map(String::as_str)
    }
}

/// Why a D3 document was refused. `line` is 1-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlError {
    /// A line does not match the accepted shape.
    Syntax { line: usize },
    /// A key appears twice at the same level.
    DuplicateKey { line: usize },
    /// A component item lacks one of `name`, `path`, `role`.
    ComponentIncomplete { line: usize },
    /// `schema` is present but is not `"crumb/v1"`.
    UnsupportedSchema,
}

/// Does the first meaningful line start a D3 document (`schema:` at column 0)?
/// Lines end at `\n` or `\r\n`, as in [`parse`].
pub fn looks_like_yaml_v1(text: &str) -> bool {
    text.lines()
        .find(|l| !is_blank_or_comment(l))
        .is_some_and(|l| l.starts_with("schema:"))
}

fn is_blank_or_comment(line: &str) -> bool {
    line.trim_matches(' ').is_empty() || line.starts_with('#')
}

fn is_key(k: &str) -> bool {
    let mut cs = k.chars();
    matches!(cs.next(), Some('a'..='z' | '_'))
        && cs.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

/// Parse `"..."` occupying the whole of `s`; only `\"` and `\\` escapes.
fn quoted(s: &str) -> Option<String> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                _ => return None,
            },
            '"' => return None,
            c if c.is_control() => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// Split `key: "value"` (exact single space after the colon).
fn key_value(s: &str) -> Option<(&str, String)> {
    let (k, rest) = s.split_once(": ")?;
    if !is_key(k) {
        return None;
    }
    Some((k, quoted(rest)?))
}

#[derive(Default)]
struct Partial {
    name: Option<String>,
    path: Option<String>,
    role: Option<String>,
    line: usize,
}

impl Partial {
    fn set(&mut self, k: &str, v: String, line: usize) -> Result<(), YamlError> {
        let slot = match k {
            "name" => &mut self.name,
            "path" => &mut self.path,
            "role" => &mut self.role,
            _ => return Err(YamlError::Syntax { line }),
        };
        if slot.is_some() {
            return Err(YamlError::DuplicateKey { line });
        }
        *slot = Some(v);
        Ok(())
    }

    fn finish(self) -> Result<YamlComponent, YamlError> {
        match (self.name, self.path, self.role) {
            (Some(name), Some(path), Some(role)) => Ok(YamlComponent { name, path, role }),
            _ => Err(YamlError::ComponentIncomplete { line: self.line }),
        }
    }
}

/// Parse a D3 document. The caller has already checked [`looks_like_yaml_v1`].
pub fn parse(text: &str) -> Result<YamlCrumbV1, YamlError> {
    let mut fields = BTreeMap::new();
    let mut schema: Option<String> = None;
    let mut components: Option<Vec<YamlComponent>> = None;
    let mut in_components = false;
    let mut current: Option<Partial> = None;

    // Same line splitting as [`looks_like_yaml_v1`]: `\n` or `\r\n` ends a line, so a CRLF file
    // parses exactly like its LF form. A bare `\r` elsewhere stays in the line and is refused.
    for (idx, line) in text.lines().enumerate() {
        let n = idx + 1;
        if is_blank_or_comment(line) {
            continue;
        }
        if let Some(item) = line.strip_prefix("  - ") {
            if !in_components {
                return Err(YamlError::Syntax { line: n });
            }
            if let Some(done) = current.take() {
                components.get_or_insert_with(Vec::new).push(done.finish()?);
            }
            let (k, v) = key_value(item).ok_or(YamlError::Syntax { line: n })?;
            let mut p = Partial {
                line: n,
                ..Partial::default()
            };
            p.set(k, v, n)?;
            current = Some(p);
            continue;
        }
        if let Some(cont) = line.strip_prefix("    ") {
            let p = current.as_mut().ok_or(YamlError::Syntax { line: n })?;
            let (k, v) = key_value(cont).ok_or(YamlError::Syntax { line: n })?;
            p.set(k, v, n)?;
            continue;
        }
        // Top-level line ends any open component list.
        if let Some(done) = current.take() {
            components.get_or_insert_with(Vec::new).push(done.finish()?);
        }
        in_components = false;
        if line == "components:" {
            if components.is_some() {
                return Err(YamlError::DuplicateKey { line: n });
            }
            components = Some(Vec::new());
            in_components = true;
            continue;
        }
        let (k, v) = key_value(line).ok_or(YamlError::Syntax { line: n })?;
        if k == "components" {
            return Err(YamlError::Syntax { line: n });
        }
        if k == "schema" {
            if schema.is_some() {
                return Err(YamlError::DuplicateKey { line: n });
            }
            schema = Some(v);
        } else if fields.insert(k.to_string(), v).is_some() {
            return Err(YamlError::DuplicateKey { line: n });
        }
    }
    if let Some(done) = current.take() {
        components.get_or_insert_with(Vec::new).push(done.finish()?);
    }
    match schema.as_deref() {
        Some(YAML_V1_SCHEMA) => Ok(YamlCrumbV1 {
            fields,
            components: components.unwrap_or_default(),
        }),
        Some(_) => Err(YamlError::UnsupportedSchema),
        None => Err(YamlError::Syntax { line: 1 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synapse_root_shape() {
        let doc = "schema: \"crumb/v1\"\nrepository: \"aien-spark/synapse\"\nsummary: \"S \\\"q\\\"\"\ncomponents:\n  - name: \"a\"\n    path: \"crates/a\"\n    role: \"A\"\n  - name: \"b\"\n    path: \"crates/b\"\n    role: \"B\"\n";
        assert!(looks_like_yaml_v1(doc));
        let y = parse(doc).unwrap();
        assert_eq!(y.summary(), Some("S \"q\""));
        assert_eq!(y.fields.get("repository").unwrap(), "aien-spark/synapse");
        assert_eq!(y.components.len(), 2);
        assert_eq!(y.components[1].path, "crates/b");
    }

    #[test]
    fn refuses_off_shape_documents() {
        let cases: [(&str, YamlError); 6] = [
            ("schema: \"crumb/v2\"\n", YamlError::UnsupportedSchema),
            (
                "schema: \"crumb/v1\"\nsummary: bare\n",
                YamlError::Syntax { line: 2 },
            ),
            (
                "schema: \"crumb/v1\"\nsummary: \"a\"\nsummary: \"b\"\n",
                YamlError::DuplicateKey { line: 3 },
            ),
            (
                "schema: \"crumb/v1\"\ncomponents:\n  - name: \"a\"\n    path: \"p\"\n",
                YamlError::ComponentIncomplete { line: 3 },
            ),
            (
                "schema: \"crumb/v1\"\ncomponents:\n  - name: \"a\"\n    owner: \"x\"\n",
                YamlError::Syntax { line: 4 },
            ),
            (
                "schema: \"crumb/v1\"\n  - name: \"a\"\n",
                YamlError::Syntax { line: 2 },
            ),
        ];
        for (doc, want) in cases {
            assert_eq!(parse(doc), Err(want), "{doc:?}");
        }
    }

    #[test]
    fn crlf_parses_like_lf_and_bare_cr_is_refused() {
        let lf = "schema: \"crumb/v1\"\nsummary: \"s\"\ncomponents:\n  - name: \"a\"\n    path: \"p\"\n    role: \"r\"\n";
        let crlf = lf.replace('\n', "\r\n");
        assert!(looks_like_yaml_v1(&crlf));
        assert_eq!(parse(&crlf), parse(lf));
        assert!(parse(lf).is_ok());
        let bare_cr = "schema: \"crumb/v1\"\nsummary: \"s\"\r\rnext: \"x\"\n";
        assert!(looks_like_yaml_v1(bare_cr));
        assert_eq!(parse(bare_cr), Err(YamlError::Syntax { line: 2 }));
    }
}
