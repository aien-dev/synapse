//! Thin, failure-reporting wrapper around the `git` command-line tool.

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Captured outcome of one `git` invocation.
#[derive(Debug)]
pub struct GitRun {
    /// Exit code (`None` if terminated by a signal).
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl GitRun {
    pub fn stdout_trimmed(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }

    pub fn stderr_tail(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let trimmed = text.trim();
        let start = trimmed.len().saturating_sub(400);
        let mut idx = start;
        while !trimmed.is_char_boundary(idx) {
            idx += 1;
        }
        trimmed[idx..].to_string()
    }
}

/// Run `git -C <dir> [-c k=v]... <args>` with optional extra environment and stdin bytes.
/// Stdin is written from a helper thread so large outputs cannot deadlock the pipe.
pub fn run_git(
    dir: &Path,
    config: &[(&str, &str)],
    env: &[(&str, &OsStr)],
    args: &[&str],
    stdin: Option<Vec<u8>>,
) -> Result<GitRun, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir);
    for (k, v) in config {
        cmd.arg("-c").arg(format!("{k}={v}"));
    }
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn git {}: {e}", args.join(" ")))?;
    let writer = match stdin {
        Some(data) => {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| format!("git {}: stdin pipe unavailable", args.join(" ")))?;
            Some(std::thread::spawn(move || pipe.write_all(&data)))
        }
        None => None,
    };
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait git {}: {e}", args.join(" ")))?;
    let write_result = match writer {
        Some(handle) => handle
            .join()
            .map_err(|_| format!("git {}: stdin writer thread panicked", args.join(" ")))?,
        None => Ok(()),
    };
    let run = GitRun {
        code: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    };
    if let Err(e) = write_result {
        if run.code != Some(0) {
            return Err(format!(
                "git {} failed (exit {:?}, stdin write error {e}): {}",
                args.join(" "),
                run.code,
                run.stderr_tail()
            ));
        }
    }
    Ok(run)
}

/// Run git and require exit status 0, returning stdout.
pub fn git_ok(
    dir: &Path,
    config: &[(&str, &str)],
    env: &[(&str, &OsStr)],
    args: &[&str],
    stdin: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let run = run_git(dir, config, env, args, stdin)?;
    if run.code != Some(0) {
        return Err(format!(
            "git {} failed (exit {:?}): {}",
            args.join(" "),
            run.code,
            run.stderr_tail()
        ));
    }
    Ok(run.stdout)
}

/// Run git without extra config, environment, or stdin and return trimmed stdout.
pub fn git_line(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = git_ok(dir, &[], &[], args, None)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}
