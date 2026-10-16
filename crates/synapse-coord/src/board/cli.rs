//! `synapse-coord board ...`: the command-line face of the board (filled in with the CLI commit).

/// Run a board subcommand; returns the process exit code.
pub fn run(_args: &[String]) -> i32 {
    eprintln!("synapse-coord board: no subcommands yet");
    1
}
