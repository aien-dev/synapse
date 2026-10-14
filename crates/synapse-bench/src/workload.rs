//! Deterministic synthetic proposal workloads on top of a real base tree.
//!
//! Edit content is synthetic (inserted comment-style lines, new small text files,
//! deletions of existing files); the base tree it applies to is real. Every arm in a
//! given (tier, repetition) cell receives exactly the same proposals.

use crate::fixture::{EditableFile, BENCH_PATH_PREFIX};
use crate::rng::SplitMix64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synapse_core::FileMode;

/// Mutation applied to one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOp {
    Upsert {
        mode: FileMode,
        content: Arc<Vec<u8>>,
    },
    Delete,
}

/// One path-level edit inside a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    pub path: String,
    pub op: EditOp,
}

/// One agent proposal against the pinned base commit. `edits` are sorted by path
/// (byte order) and unique, as `ChangesetEnvelope::validate` requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub agent: usize,
    pub index: usize,
    pub summary: String,
    pub edits: Vec<FileEdit>,
}

impl Proposal {
    /// Sum of upserted content bytes.
    pub fn content_bytes(&self) -> u64 {
        self.edits
            .iter()
            .map(|e| match &e.op {
                EditOp::Upsert { content, .. } => content.len() as u64,
                EditOp::Delete => 0,
            })
            .sum()
    }
}

fn synthetic_lines(rng: &mut SplitMix64, tag: &str, count: usize) -> String {
    let mut s = String::new();
    for i in 0..count {
        s.push_str(&format!(
            "// synapse-gate4 {tag} line {i} {}\n",
            rng.hex16()
        ));
    }
    s
}

/// Insert a synthetic hunk of 3..=12 lines at a random line boundary.
fn insert_hunk(rng: &mut SplitMix64, original: &[u8], tag: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(original);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let at = rng.below(lines.len() + 1);
    let count = rng.range(3, 12);
    let hunk = synthetic_lines(rng, tag, count);
    let mut out = String::with_capacity(original.len() + hunk.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        if i == at {
            out.push_str(&hunk);
        }
        out.push_str(line);
    }
    if at == lines.len() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&hunk);
    }
    out.into_bytes()
}

fn finalize(agent: usize, index: usize, mut edits: Vec<FileEdit>) -> Proposal {
    edits.sort_by(|a, b| a.path.cmp(&b.path));
    edits.dedup_by(|a, b| a.path == b.path);
    Proposal {
        agent,
        index,
        summary: format!("gate4 synthetic proposal agent {agent} index {index}"),
        edits,
    }
}

/// Generate proposal `index` for `agent`. Mix per proposal: 1 edit (50%), 2 (35%),
/// or 3 (15%); each edit modifies an existing file (70%), adds a new file under
/// [`BENCH_PATH_PREFIX`] (20%), or deletes an existing file (10%).
pub fn generate_proposal(
    seed: u64,
    stream: &[u64],
    agent: usize,
    index: usize,
    files: &[EditableFile],
) -> Proposal {
    let mut labels = stream.to_vec();
    labels.extend_from_slice(&[agent as u64, index as u64]);
    let mut rng = SplitMix64::derive(seed, &labels);
    let roll = rng.below(100);
    let n_edits = if roll < 50 {
        1
    } else if roll < 85 {
        2
    } else {
        3
    };
    let mut edits: Vec<FileEdit> = Vec::new();
    for j in 0..n_edits {
        let kind = if files.is_empty() { 75 } else { rng.below(100) };
        if !(70..90).contains(&kind) {
            // Modify or delete an existing file not yet touched by this proposal.
            let mut chosen = None;
            for _ in 0..4 {
                let f = &files[rng.below(files.len())];
                if !edits.iter().any(|e| e.path == f.path) {
                    chosen = Some(f);
                    break;
                }
            }
            let Some(f) = chosen else { continue };
            let op = if kind < 70 {
                let tag = format!("a{agent} p{index} e{j}");
                EditOp::Upsert {
                    mode: FileMode::Regular644,
                    content: Arc::new(insert_hunk(&mut rng, &f.content, &tag)),
                }
            } else {
                EditOp::Delete
            };
            edits.push(FileEdit {
                path: f.path.clone(),
                op,
            });
        } else {
            let path = format!("{BENCH_PATH_PREFIX}/a{agent:03}/p{index:05}-e{j}.txt");
            let lines = rng.range(4, 40);
            let tag = format!("new a{agent} p{index} e{j}");
            edits.push(FileEdit {
                path,
                op: EditOp::Upsert {
                    mode: FileMode::Regular644,
                    content: Arc::new(synthetic_lines(&mut rng, &tag, lines).into_bytes()),
                },
            });
        }
    }
    if edits.is_empty() {
        let path = format!("{BENCH_PATH_PREFIX}/a{agent:03}/p{index:05}-fallback.txt");
        let tag = format!("fallback a{agent} p{index}");
        edits.push(FileEdit {
            path,
            op: EditOp::Upsert {
                mode: FileMode::Regular644,
                content: Arc::new(synthetic_lines(&mut rng, &tag, 6).into_bytes()),
            },
        });
    }
    finalize(agent, index, edits)
}

/// Generate `ops_per_agent` proposals for each of `agents` agents. The stream labels
/// are `[rep, agents]`, so all arms in one (tier, rep) cell get identical proposals and
/// a shorter run (for example the capped G1 arm) receives a prefix of each agent's list.
pub fn generate_write_workload(
    seed: u64,
    rep: usize,
    agents: usize,
    ops_per_agent: usize,
    files: &[EditableFile],
) -> Vec<Vec<Proposal>> {
    (0..agents)
        .map(|a| {
            (0..ops_per_agent)
                .map(|k| generate_proposal(seed, &[rep as u64, agents as u64], a, k, files))
                .collect()
        })
        .collect()
}

/// Role a proposal plays in the conflict-correctness scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScenarioGroup {
    /// Whole-file rewrite of the shared hotspot file.
    Hotspot,
    /// Single-line change in a distinct region of the shared mergeable file.
    DisjointHunk,
    /// Adds a file at `<dir>/node`.
    FileSide,
    /// Adds a file below `<dir>/node/`.
    DirectorySide,
    /// Modifies the shared modify/delete file.
    ModifySide,
    /// Deletes the shared modify/delete file.
    DeleteSide,
    /// Adds the shared identical new file (byte-identical content).
    IdenticalAdd,
    /// Deletes the shared identically deleted file.
    IdenticalDelete,
    /// Edits only its own file.
    Distinct,
}

/// Ground-truth relation between two scenario proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PairClass {
    HotspotRewrite,
    DisjointHunksSameFile,
    FileDirectoryCollision,
    ModifyDelete,
    IdenticalChange,
    DistinctPaths,
}

impl PairClass {
    /// Expected under Synapse's documented path-level rule: same path with a different
    /// operation, or a file/directory prefix collision between two upserts.
    pub fn path_level_conflict_expected(self) -> bool {
        matches!(
            self,
            Self::HotspotRewrite
                | Self::DisjointHunksSameFile
                | Self::FileDirectoryCollision
                | Self::ModifyDelete
        )
    }

    /// Expected outcome of a Git three-way merge (`git merge-tree --write-tree`).
    pub fn git_conflict_expected(self) -> bool {
        matches!(
            self,
            Self::HotspotRewrite | Self::FileDirectoryCollision | Self::ModifyDelete
        )
    }
}

/// Classify a pair purely from the declared generator roles (not from paths).
pub fn classify_pair(a: ScenarioGroup, b: ScenarioGroup) -> PairClass {
    use ScenarioGroup as G;
    match (a, b) {
        (G::Hotspot, G::Hotspot) => PairClass::HotspotRewrite,
        (G::DisjointHunk, G::DisjointHunk) => PairClass::DisjointHunksSameFile,
        (G::FileSide, G::DirectorySide) | (G::DirectorySide, G::FileSide) => {
            PairClass::FileDirectoryCollision
        }
        (G::ModifySide, G::DeleteSide) | (G::DeleteSide, G::ModifySide) => PairClass::ModifyDelete,
        (G::IdenticalAdd, G::IdenticalAdd) | (G::IdenticalDelete, G::IdenticalDelete) => {
            PairClass::IdenticalChange
        }
        _ => PairClass::DistinctPaths,
    }
}

/// A scenario proposal plus its declared role.
#[derive(Debug, Clone)]
pub struct ScenarioProposal {
    pub proposal: Proposal,
    pub group: ScenarioGroup,
}

fn replace_line(original: &[u8], line_idx: usize, new_line: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(original);
    let mut out = String::with_capacity(original.len() + new_line.len());
    for (i, line) in text.split_inclusive('\n').enumerate() {
        if i == line_idx {
            out.push_str(new_line);
            out.push('\n');
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

/// Minimum line count of the file used for disjoint-hunk edits.
pub const MERGEABLE_MIN_LINES: usize = 60;

/// Build the conflict-correctness scenario: 4 hotspot rewrites, 3 disjoint single-line
/// edits of one file, a file/directory collision pair, a modify/delete pair, two
/// identical adds (the second also edits its own file), two identical deletes, and 8
/// proposals that each edit a distinct file. Needs at least 14 editable files, one of
/// them with [`MERGEABLE_MIN_LINES`] or more lines.
pub fn build_conflict_scenario(
    seed: u64,
    files: &[EditableFile],
) -> Result<Vec<ScenarioProposal>, String> {
    let mut rng = SplitMix64::derive(seed, &[0x0C0F_11C7]);
    let mut order: Vec<usize> = (0..files.len()).collect();
    rng.shuffle(&mut order);
    let mergeable_pos = order
        .iter()
        .position(|&i| files[i].line_count >= MERGEABLE_MIN_LINES)
        .ok_or("no editable file with enough lines for disjoint-hunk edits")?;
    let mergeable = &files[order.remove(mergeable_pos)];
    if order.len() < 13 {
        return Err(format!(
            "conflict scenario needs 14 editable files, found {}",
            order.len() + 1
        ));
    }
    let hotspot = &files[order[0]];
    let moddel = &files[order[1]];
    let iddel = &files[order[2]];
    let distinct: Vec<&EditableFile> = order[3..12].iter().map(|&i| &files[i]).collect();

    let mut out: Vec<ScenarioProposal> = Vec::new();
    let mut push = |group: ScenarioGroup, edits: Vec<FileEdit>| {
        let idx = out.len();
        out.push(ScenarioProposal {
            proposal: finalize(1000 + idx, idx, edits),
            group,
        });
    };
    let upsert = |path: &str, bytes: Vec<u8>| FileEdit {
        path: path.to_string(),
        op: EditOp::Upsert {
            mode: FileMode::Regular644,
            content: Arc::new(bytes),
        },
    };

    for h in 0..4 {
        let lines = rng.range(20, 40);
        let body = synthetic_lines(&mut rng, &format!("hotspot rewrite {h}"), lines);
        push(
            ScenarioGroup::Hotspot,
            vec![upsert(&hotspot.path, body.into_bytes())],
        );
    }
    let n = mergeable.line_count;
    for (k, line_idx) in [1usize, n / 2, n - 2].into_iter().enumerate() {
        let new_line = format!("// synapse-gate4 disjoint hunk {k} {}", rng.hex16());
        push(
            ScenarioGroup::DisjointHunk,
            vec![upsert(
                &mergeable.path,
                replace_line(&mergeable.content, line_idx, &new_line),
            )],
        );
    }
    let fd_file = format!("{BENCH_PATH_PREFIX}/fd/node");
    let fd_child = format!("{BENCH_PATH_PREFIX}/fd/node/child.txt");
    push(
        ScenarioGroup::FileSide,
        vec![upsert(&fd_file, b"file side\n".to_vec())],
    );
    push(
        ScenarioGroup::DirectorySide,
        vec![upsert(&fd_child, b"directory side\n".to_vec())],
    );
    push(
        ScenarioGroup::ModifySide,
        vec![upsert(
            &moddel.path,
            insert_hunk(&mut rng, &moddel.content, "modify side"),
        )],
    );
    push(
        ScenarioGroup::DeleteSide,
        vec![FileEdit {
            path: moddel.path.clone(),
            op: EditOp::Delete,
        }],
    );
    let shared_path = format!("{BENCH_PATH_PREFIX}/identical/shared.txt");
    let shared_body = synthetic_lines(&mut rng, "identical add", 8).into_bytes();
    push(
        ScenarioGroup::IdenticalAdd,
        vec![upsert(&shared_path, shared_body.clone())],
    );
    push(
        ScenarioGroup::IdenticalAdd,
        vec![
            upsert(&shared_path, shared_body),
            upsert(
                &distinct[8].path,
                insert_hunk(&mut rng, &distinct[8].content, "identical add extra"),
            ),
        ],
    );
    for _ in 0..2 {
        push(
            ScenarioGroup::IdenticalDelete,
            vec![FileEdit {
                path: iddel.path.clone(),
                op: EditOp::Delete,
            }],
        );
    }
    for (d, f) in distinct.iter().take(8).enumerate() {
        push(
            ScenarioGroup::Distinct,
            vec![upsert(
                &f.path,
                insert_hunk(&mut rng, &f.content, &format!("distinct {d}")),
            )],
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(n: usize, lines: usize) -> Vec<EditableFile> {
        (0..n)
            .map(|i| {
                let body: String = (0..lines).map(|l| format!("file {i} line {l}\n")).collect();
                EditableFile {
                    path: format!("src/f{i:03}.rs"),
                    content: Arc::new(body.into_bytes()),
                    line_count: lines,
                }
            })
            .collect()
    }

    #[test]
    fn write_workload_is_deterministic_sorted_and_unique() {
        let f = files(30, 20);
        let a = generate_write_workload(9, 0, 3, 20, &f);
        let b = generate_write_workload(9, 0, 3, 20, &f);
        assert_eq!(a, b);
        let c = generate_write_workload(9, 1, 3, 20, &f);
        assert_ne!(a, c);
        for agent in &a {
            assert_eq!(agent.len(), 20);
            for p in agent {
                assert!(!p.edits.is_empty() && p.edits.len() <= 3);
                for w in p.edits.windows(2) {
                    assert!(w[0].path < w[1].path, "edits must be strictly sorted");
                }
            }
        }
        // A shorter run is a prefix of the longer run for every agent.
        let short = generate_write_workload(9, 0, 3, 5, &f);
        for (s, l) in short.iter().zip(a.iter()) {
            assert_eq!(s.as_slice(), &l[..5]);
        }
    }

    #[test]
    fn hunk_insertion_preserves_original_lines() {
        let mut rng = SplitMix64::new(3);
        let original = b"a\nb\nc\n";
        let edited = insert_hunk(&mut rng, original, "t");
        let text = String::from_utf8(edited).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with("// synapse-gate4"))
            .collect();
        assert_eq!(kept, vec!["a", "b", "c"]);
    }

    #[test]
    fn scenario_has_expected_shape_and_classes() {
        let mut f = files(20, 30);
        f[5] = EditableFile {
            line_count: 80,
            content: Arc::new(
                (0..80)
                    .map(|l| format!("long {l}\n"))
                    .collect::<String>()
                    .into_bytes(),
            ),
            ..f[5].clone()
        };
        let s = build_conflict_scenario(5, &f).unwrap();
        assert_eq!(s.len(), 23);
        let count = |g: ScenarioGroup| s.iter().filter(|p| p.group == g).count();
        assert_eq!(count(ScenarioGroup::Hotspot), 4);
        assert_eq!(count(ScenarioGroup::DisjointHunk), 3);
        assert_eq!(count(ScenarioGroup::Distinct), 8);
        assert_eq!(
            classify_pair(ScenarioGroup::FileSide, ScenarioGroup::DirectorySide),
            PairClass::FileDirectoryCollision
        );
        assert!(PairClass::DisjointHunksSameFile.path_level_conflict_expected());
        assert!(!PairClass::DisjointHunksSameFile.git_conflict_expected());
        assert!(!PairClass::IdenticalChange.path_level_conflict_expected());
        assert!(build_conflict_scenario(5, &files(20, 10)).is_err());
    }
}
