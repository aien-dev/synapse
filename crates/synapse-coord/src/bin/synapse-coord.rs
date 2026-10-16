//! Thin command-line front end over `synapse_coord`, mirroring `crumb claim|update|whisper|
//! close|sniff` output lines and exit codes (0 ok, 1 error, 2 blocked/refused).
//!
//! usage: synapse-coord --store DIR --top WORKSPACE [--expect-store-id ID] [--branch B --head H --base X]
//!                      [--synapse LANE REVISION BASE] [--session S] [--no-tree] <command> ...
//!   claim <agent> <dir> <target> <intent> [ttl]
//!   update <agent> <dir> <focus> [ttl]
//!   whisper <from> <dir> <to|-> <message> [priority] [target_file]
//!   close <agent> <dir> <target> [action] [message]
//!   sniff <agent> <dir>
//!   id                  print the store id, creating the marker if absent (--top optional)
//!
//! --expect-store-id ID refuses (exit 1) unless the store carries that STORE_ID marker.
//!
//! synapse-coord canon <file>   parse a record and print it re-serialized (format parity check)

use std::process::ExitCode;
use synapse_coord::{
    ClaimOutcome, CloseOutcome, CoordStore, FsOracle, Holder, NoOracle, PathOracle, StoreId,
    Workspace,
};

fn die(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("synapse-coord: {msg}");
    ExitCode::from(1)
}

fn ttl(s: Option<&String>) -> Result<Option<i64>, String> {
    match s {
        None => Ok(None),
        Some(s) => s
            .parse::<i64>()
            .ok()
            .filter(|v| *v >= 0)
            .map(Some)
            .ok_or_else(|| format!("bad ttl: {s}")),
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "canon" {
        return match synapse_coord::read_record_file(std::path::Path::new(&args[1]))
            .ok()
            .flatten()
            .and_then(|b| synapse_coord::json::parse(&b))
        {
            Some(j) => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&j.dump());
                ExitCode::SUCCESS
            }
            None => die(format!("{} is not valid JSON", args[1])),
        };
    }
    let (mut store, mut top, mut expect) = (None, None, None);
    let mut holder = Holder::default();
    let mut no_tree = false;
    while args.first().is_some_and(|a| a.starts_with("--")) {
        let flag = args.remove(0);
        let mut take = || {
            if args.is_empty() {
                None
            } else {
                Some(args.remove(0))
            }
        };
        let ok = match flag.as_str() {
            "--store" => take().map(|v| store = Some(v)).is_some(),
            "--top" => take().map(|v| top = Some(v)).is_some(),
            "--expect-store-id" => match take().map(|v| StoreId::parse_hex(&v)) {
                Some(Some(id)) => {
                    expect = Some(id);
                    true
                }
                _ => false,
            },
            "--branch" => take().map(|v| holder.branch = v).is_some(),
            "--head" => take().map(|v| holder.head = v).is_some(),
            "--base" => take().map(|v| holder.base = v).is_some(),
            "--session" => take().map(|v| holder.session = Some(v)).is_some(),
            "--synapse" => match (take(), take(), take()) {
                (Some(l), Some(r), Some(b)) => {
                    let session = holder.session.take();
                    holder = Holder::synapse(&l, &r, &b);
                    holder.session = session;
                    true
                }
                _ => false,
            },
            "--no-tree" => {
                no_tree = true;
                true
            }
            _ => false,
        };
        if !ok {
            return die(format!("bad or incomplete flag {flag}"));
        }
    }
    let Some(store) = store else {
        return die("--store is required");
    };
    let cs = match expect {
        Some(id) => match CoordStore::open_expecting(store, id) {
            Ok(cs) => cs,
            Err(e) => return die(e),
        },
        None => CoordStore::open(store),
    };
    if args.len() == 1 && args[0] == "id" {
        return match cs.ensure_store_id() {
            Ok(id) => {
                println!("{id}");
                ExitCode::SUCCESS
            }
            Err(e) => die(e),
        };
    }
    let Some(top) = top else {
        return die("--top is required");
    };
    let oracle: Box<dyn PathOracle> = if no_tree {
        Box::new(NoOracle)
    } else {
        Box::new(FsOracle(top.clone().into()))
    };
    let ws = Workspace::with_oracle(top.clone(), holder, oracle);
    let a = &args;
    let n = a.len();
    let cmd = a.first().map(String::as_str).unwrap_or("");
    let res: Result<u8, String> = (|| {
        match cmd {
        "claim" if n >= 5 => {
            let t = ttl(a.get(5))?;
            match cs
                .claim(&ws, &a[1], &a[2], &a[3], &a[4], t)
                .map_err(|e| e.to_string())?
            {
                ClaimOutcome::Claimed { key } => {
                    println!(
                        "CLAIMED {key} in {} as {} on {} (ttl {}s)",
                        ws.top,
                        a[1],
                        ws.holder.branch,
                        t.unwrap_or(synapse_coord::LOCK_TTL)
                    );
                    Ok(0)
                }
                ClaimOutcome::Blocked { key, holder: h } => {
                    println!(
                        "BLOCKED {key} held by {} on branch {} (worktree {}) since {} ({})",
                        h.holder, h.branch, h.worktree, h.acquired_at, h.intent
                    );
                    Ok(2)
                }
            }
        }
        "update" if n >= 4 => {
            let t = ttl(a.get(4))?;
            cs.update(&ws, &a[1], &a[2], &a[3], t)
                .map_err(|e| e.to_string())?;
            println!(
                "SCENT {} in {}: {} (ttl {}s)",
                a[1],
                ws.top,
                a[3],
                t.unwrap_or(synapse_coord::SCENT_TTL)
            );
            Ok(0)
        }
        "whisper" if n >= 5 => {
            cs.whisper(
                &ws,
                &a[1],
                &a[2],
                Some(a[3].as_str()),
                &a[4],
                a.get(5).map(String::as_str),
                a.get(6).map(String::as_str),
            )
            .map_err(|e| e.to_string())?;
            let to = if a[3] == "-" { "(broadcast)" } else { a[3].as_str() };
            println!("WHISPER {} -> {to} in {}", a[1], ws.top);
            Ok(0)
        }
        "close" if n >= 4 => {
            let action = a.get(4).map(String::as_str).unwrap_or("modify");
            match cs
                .close(&ws, &a[1], &a[2], &a[3], action, a.get(5).map(String::as_str))
                .map_err(|e| e.to_string())?
            {
                CloseOutcome::Closed { key, lock_was_held } => {
                    println!(
                        "CLOSED {key} in {} by {} ({action}){}",
                        ws.top,
                        a[1],
                        if lock_was_held { "" } else { " [no lock was held]" }
                    );
                    Ok(0)
                }
                CloseOutcome::Refused { key, holder } => {
                    println!("REFUSED: {key} is held by {holder}, not {}", a[1]);
                    Ok(2)
                }
            }
        }
        "sniff" if n >= 3 => {
            let s = cs.sniff(&ws, &a[1], &a[2]).map_err(|e| e.to_string())?;
            print!("{}", s.render(&ws, &a[1]));
            Ok(0)
        }
        _ => Err("usage: synapse-coord --store DIR --top WORKSPACE [holder flags] claim|update|whisper|close|sniff ...".into()),
    }
    })();
    match res {
        Ok(code) => ExitCode::from(code),
        Err(e) => die(e),
    }
}
