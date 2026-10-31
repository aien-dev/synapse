//! Merge tier T1 (region): line-level three-way merge of one file (ADR 0003 section 5.5,
//! section 9 step D1). See `docs/D1_MERGE_TIER_T1.md`.
//!
//! [`region_merge`] merges the versions of one file that several revisions wrote against the
//! same base version. The rule does not depend on which line diff is chosen:
//!
//! 1. **Anchors.** For each version, a base line is *forced* when every minimal line
//!    alignment (every longest common subsequence) between the base and that version matches
//!    it, and always to the same line of the version. The anchors are the base lines forced
//!    for every version.
//! 2. **Segments.** The anchors cut the base and every version into matching segments (the
//!    lines between two consecutive anchors). In each segment at most one version may differ
//!    from the base; the merged file takes that version's segment (or the base's when none
//!    differs). Two versions that change one segment are a conflict, also when they changed
//!    it identically (callers take byte-identical whole-file mutations once, before calling
//!    this).
//!
//! Why this agrees with Git: any minimal diff matches every anchor, so its changed regions for
//! one version stay inside that version's changed segments, and the regions of two versions
//! are always separated by at least one anchor line, which is the condition Git's three-way
//! merge needs for a clean result; the clean result is then the same file. `synapse-bench`
//! checks it against `git merge-file` and `git merge-tree`. The argument covers diffs that are
//! minimal; Git's histogram diff and its cost-limited Myers diff on very large inputs are not
//! always minimal, which is why the bench comparison is part of the acceptance.
//!
//! Refused as well: binary content (any NUL byte), a version that does not end with a newline,
//! and a base and version too long to align within [`MAX_ALIGNMENT_CELLS`].

use std::collections::HashMap;

/// Largest `(base lines + 1) * (version lines + 1)` [`region_merge`] aligns (two `u32` tables
/// of this many cells per version, 16 MiB each at the limit).
pub const MAX_ALIGNMENT_CELLS: usize = 1 << 22;

/// Why a region merge is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionConflict {
    /// A version contains a NUL byte.
    Binary,
    /// A non-empty version does not end with a newline.
    NoFinalNewline,
    /// The base and a version are too long to align within [`MAX_ALIGNMENT_CELLS`].
    TooLarge,
    /// Versions `a` and `b` both change the base lines between two anchors, starting at base
    /// line `line` (0-based).
    Overlap { a: usize, b: usize, line: usize },
}

impl std::fmt::Display for RegionConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegionConflict::Binary => write!(f, "binary content"),
            RegionConflict::NoFinalNewline => write!(f, "a version does not end with a newline"),
            RegionConflict::TooLarge => write!(
                f,
                "the file is too long to align (more than {MAX_ALIGNMENT_CELLS} cells)"
            ),
            RegionConflict::Overlap { a, b, line } => write!(
                f,
                "versions {a} and {b} both change the region starting at base line {}",
                line + 1
            ),
        }
    }
}

fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split_inclusive(|b| *b == b'\n').collect()
}

fn check_text(bytes: &[u8]) -> Result<(), RegionConflict> {
    if bytes.contains(&0) {
        return Err(RegionConflict::Binary);
    }
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err(RegionConflict::NoFinalNewline);
    }
    Ok(())
}

/// For each line of `a`, the line of `b` it is matched to in every longest common subsequence
/// of `a` and `b`, or `None` when some longest common subsequence leaves it unmatched or
/// matches it elsewhere.
fn forced_matches(a: &[u32], b: &[u32]) -> Result<Vec<Option<usize>>, RegionConflict> {
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    if (n + 1).saturating_mul(w) > MAX_ALIGNMENT_CELLS {
        return Err(RegionConflict::TooLarge);
    }
    // f[i * w + j] = LCS(a[..i], b[..j]); s[i * w + j] = LCS(a[i..], b[j..]).
    let mut f = vec![0u32; (n + 1) * w];
    for i in 1..=n {
        for j in 1..=m {
            f[i * w + j] = if a[i - 1] == b[j - 1] {
                f[(i - 1) * w + j - 1] + 1
            } else {
                f[(i - 1) * w + j].max(f[i * w + j - 1])
            };
        }
    }
    let mut s = vec![0u32; (n + 1) * w];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            s[i * w + j] = if a[i] == b[j] {
                s[(i + 1) * w + j + 1] + 1
            } else {
                s[(i + 1) * w + j].max(s[i * w + j + 1])
            };
        }
    }
    let total = f[n * w + m];
    let mut out = vec![None; n];
    for (i, slot) in out.iter_mut().enumerate() {
        // Some optimal alignment leaves line i unmatched: not forced.
        if (0..=m).any(|j| f[i * w + j] + s[(i + 1) * w + j] == total) {
            continue;
        }
        let mut partners =
            (0..m).filter(|&j| a[i] == b[j] && f[i * w + j] + 1 + s[(i + 1) * w + j + 1] == total);
        if let (Some(j), None) = (partners.next(), partners.next()) {
            *slot = Some(j);
        }
    }
    Ok(out)
}

/// Line-level three-way merge of `versions` of one file against `base` (see the module
/// documentation). `Ok` holds the merged bytes.
pub fn region_merge<'a>(base: &'a [u8], versions: &[&'a [u8]]) -> Result<Vec<u8>, RegionConflict> {
    check_text(base)?;
    for v in versions {
        check_text(v)?;
    }
    let mut ids: HashMap<&[u8], u32> = HashMap::new();
    let mut text: Vec<&[u8]> = Vec::new();
    let mut intern = |bytes: &'a [u8]| -> Vec<u32> {
        split_lines(bytes)
            .into_iter()
            .map(|line| {
                *ids.entry(line).or_insert_with(|| {
                    text.push(line);
                    (text.len() - 1) as u32
                })
            })
            .collect()
    };
    let base_ids = intern(base);
    let version_ids: Vec<Vec<u32>> = versions.iter().map(|v| intern(v)).collect();
    let forced: Vec<Vec<Option<usize>>> = version_ids
        .iter()
        .map(|v| forced_matches(&base_ids, v))
        .collect::<Result<_, _>>()?;
    // Anchors: base lines forced in every version, with their partner in each version. The
    // partners increase with the base line (an alignment never crosses), and the end of the
    // files closes the last segment.
    let mut cuts: Vec<(usize, Vec<usize>)> = Vec::new();
    for i in 0..base_ids.len() {
        let partners: Option<Vec<usize>> = forced.iter().map(|f| f[i]).collect();
        if let Some(p) = partners {
            cuts.push((i, p));
        }
    }
    let anchors = cuts.len();
    cuts.push((base_ids.len(), version_ids.iter().map(Vec::len).collect()));
    let mut out: Vec<u32> = Vec::with_capacity(base_ids.len());
    let mut base_at = 0;
    let mut ver_at = vec![0usize; versions.len()];
    for (k, (cut, partners)) in cuts.iter().enumerate() {
        let base_seg = &base_ids[base_at..*cut];
        let mut changed: Option<(usize, &[u32])> = None;
        for (v, ids) in version_ids.iter().enumerate() {
            let seg = &ids[ver_at[v]..partners[v]];
            if seg != base_seg {
                if let Some((first, _)) = changed {
                    return Err(RegionConflict::Overlap {
                        a: first,
                        b: v,
                        line: base_at,
                    });
                }
                changed = Some((v, seg));
            }
        }
        out.extend_from_slice(changed.map_or(base_seg, |(_, seg)| seg));
        if k < anchors {
            out.push(base_ids[*cut]);
        }
        base_at = cut + 1;
        for (v, p) in partners.iter().enumerate() {
            ver_at[v] = p + 1;
        }
    }
    Ok(out
        .into_iter()
        .flat_map(|id| text[id as usize].iter().copied())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn lines(n: usize, tag: &str) -> String {
        (0..n).map(|i| format!("{tag} {i}\n")).collect()
    }

    fn edit(base: &str, line: usize, new: &str) -> String {
        base.split_inclusive('\n')
            .enumerate()
            .map(|(i, l)| {
                if i == line {
                    format!("{new}\n")
                } else {
                    l.to_string()
                }
            })
            .collect()
    }

    /// Every longest-common-subsequence alignment of `a` and `b`, as sets of matched pairs.
    fn all_optimal(a: &[u32], b: &[u32]) -> Vec<BTreeSet<(usize, usize)>> {
        fn go(
            a: &[u32],
            b: &[u32],
            i: usize,
            j: usize,
            cur: &mut Vec<(usize, usize)>,
            out: &mut Vec<Vec<(usize, usize)>>,
        ) {
            if i == a.len() || j == b.len() {
                out.push(cur.clone());
                return;
            }
            if a[i] == b[j] {
                cur.push((i, j));
                go(a, b, i + 1, j + 1, cur, out);
                cur.pop();
            }
            go(a, b, i + 1, j, cur, out);
            go(a, b, i, j + 1, cur, out);
        }
        let mut all = Vec::new();
        go(a, b, 0, 0, &mut Vec::new(), &mut all);
        let best = all.iter().map(Vec::len).max().unwrap_or(0);
        all.into_iter()
            .filter(|x| x.len() == best)
            .map(|x| x.into_iter().collect())
            .collect()
    }

    /// The forced matches equal the intersection of every optimal alignment, on random small
    /// inputs over small alphabets (many repeated lines), checked by brute force.
    #[test]
    fn d1_forced_matches_are_exactly_the_pairs_every_optimal_alignment_shares() {
        let mut s = 0x0D1_u64;
        let mut next = || {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s >> 33
        };
        for _ in 0..2_000 {
            let n = (next() % 7) as usize;
            let m = (next() % 7) as usize;
            let alpha = 1 + next() % 3;
            let a: Vec<u32> = (0..n).map(|_| (next() % alpha) as u32).collect();
            let b: Vec<u32> = (0..m).map(|_| (next() % alpha) as u32).collect();
            let all = all_optimal(&a, &b);
            let mut common = all[0].clone();
            for x in &all[1..] {
                common = common.intersection(x).copied().collect();
            }
            let want: Vec<Option<usize>> = (0..n)
                .map(|i| common.iter().find(|(x, _)| *x == i).map(|(_, j)| *j))
                .collect();
            assert_eq!(forced_matches(&a, &b).unwrap(), want, "{a:?} {b:?}");
        }
    }

    #[test]
    fn d1_disjoint_single_line_edits_merge_and_touching_edits_conflict() {
        let base = lines(60, "line");
        let a = edit(&base, 10, "alpha");
        let b = edit(&base, 30, "beta");
        let c = edit(&base, 50, "gamma");
        let merged =
            region_merge(base.as_bytes(), &[a.as_bytes(), b.as_bytes(), c.as_bytes()]).unwrap();
        let want = edit(&edit(&edit(&base, 10, "alpha"), 30, "beta"), 50, "gamma");
        assert_eq!(String::from_utf8(merged).unwrap(), want);
        // One unchanged line between: clean. Adjacent lines: conflict (as Git).
        let near = edit(&base, 12, "near");
        assert!(region_merge(base.as_bytes(), &[a.as_bytes(), near.as_bytes()]).is_ok());
        let touch = edit(&base, 11, "touch");
        assert!(matches!(
            region_merge(base.as_bytes(), &[a.as_bytes(), touch.as_bytes()]),
            Err(RegionConflict::Overlap { .. })
        ));
        // Identical edits are refused here (callers take identical whole files once).
        assert!(region_merge(base.as_bytes(), &[a.as_bytes(), a.as_bytes()]).is_err());
    }

    /// A version whose edit some minimal diff places next to the other version's edit is a
    /// conflict, even when one particular alignment would separate them.
    #[test]
    fn d1_edits_that_some_minimal_diff_places_together_conflict() {
        // An inserted `x` in a run of `x` lines may sit right before the `b` line.
        let base = "a\nx\nx\nx\nb\nc\nd\n";
        let ins = "a\nx\nx\nx\nx\nb\nc\nd\n";
        let after = "a\nx\nx\nx\nB\nc\nd\n";
        assert!(matches!(
            region_merge(base.as_bytes(), &[ins.as_bytes(), after.as_bytes()]),
            Err(RegionConflict::Overlap { .. })
        ));
        let far = "a\nx\nx\nx\nb\nc\nD\n";
        assert_eq!(
            region_merge(base.as_bytes(), &[ins.as_bytes(), far.as_bytes()]).unwrap(),
            b"a\nx\nx\nx\nx\nb\nc\nD\n"
        );
        // Found by the `git merge-file` differential: version b moves an `x` across a `}`,
        // which one minimal diff reads as an insertion before the `}` and another as a
        // deletion of the `}` right where version a inserts `{`.
        let base = "}\n}\nline 2\nx\nx\n}\nx\n}\nx\n}\n}\nline 11\n}\n";
        let a = "}\n}\nline 2\nx\nx\n}\n{\nx\n}\nx\n}\n}\nline 11\n}\n";
        let b = "}\n}\nline 2\nx\nx\nx\n}\nx\n}\nx\n}\nB 0\n}\n";
        assert!(region_merge(base.as_bytes(), &[a.as_bytes(), b.as_bytes()]).is_err());
    }

    #[test]
    fn d1_binary_missing_final_newline_and_oversized_files_are_refused() {
        assert_eq!(
            region_merge(b"a\0\n", &[b"a\n", b"b\n"]),
            Err(RegionConflict::Binary)
        );
        assert_eq!(
            region_merge(b"a\nb\n", &[b"a\nb", b"a\nb\n"]),
            Err(RegionConflict::NoFinalNewline)
        );
        // Empty base: two versions that both add text conflict.
        assert!(region_merge(b"", &[b"a\n", b"b\n"]).is_err());
        let big = lines(3_000, "l");
        let big2 = edit(&big, 5, "x");
        assert_eq!(
            region_merge(big.as_bytes(), &[big2.as_bytes(), big.as_bytes()]),
            Err(RegionConflict::TooLarge)
        );
    }
}
