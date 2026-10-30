#!/usr/bin/env bash
# Issue #65 Stage A: fold gdb stack samples (from p65-gdb-sample.sh) into thread-sample counts.
# Usage: p65-sample-report.sh <samples.txt> <anchor-function>
# Only threads whose stack contains <anchor-function> (for example synapse_submit) are counted.
# Every such thread-sample gets:
#   state : run (user code) or wait:<syscall> <- <first recognised caller> when frame #0 is a
#           system call wrapper (futex, fdatasync, pwrite, ...)
#   phase : the callee frame directly under the anchor (where in the operation the thread is)
#   leaf  : for run samples, the leaf-most frame that names a crate or libc area. Frames from
#           std/core and frames with crate-relative paths (src/...) are skipped so that inlined
#           helpers are charged to the crate that called them.
#   incl  : for run samples, every crate present between frame #0 and the anchor (counted once
#           per thread-sample), i.e. inclusive time.
set -euo pipefail
samples=$1; anchor=$2
awk -v anchor="$anchor" '
function base(f,  a,n){ sub(/:[0-9]+$/,"",f); n=split(f,a,"/"); return a[n] }
function crate(fn,file,  a,b,n,i,c){
  if (file ~ /registry\/src\//) { n=split(file,a,"/"); for (i=1;i<n;i++) if (a[i] ~ /^index\.crates\.io/) { c=a[i+1]; sub(/-[0-9][0-9.]*$/,"",c); return c } }
  if (file ~ /crates\/synapse-/) { split(file,a,"crates/"); split(a[2],b,"/"); return b[1] ":" base(file) }
  if (file ~ /malloc\// || fn ~ /malloc|^__libc_free|^free$|calloc|realloc|cfree|_int_free|tcache/) return "libc:malloc/free";
  if (file ~ /string\// || fn ~ /memcpy|memmove|memset|memcmp|strlen/) return "libc:mem*";
  if (file ~ /^\.\.\/sysdeps|^\.\/nptl/) return "libc:" fn;
  if (file ~ /library\/alloc\//) return "rust:alloc";
  return ""
}
function flush(   i,ai,st,ph,lf,c,f0,seen){
  if (!inth || nf == 0) { inth=0; nf=0; return }
  ai=-1; for (i=0;i<nf;i++) if (fname[i]==anchor) { ai=i; break }
  if (ai >= 0) {
    total++
    f0=fname[0]; st="run"
    if (f0 ~ /^(syscall|__GI_|__libc_|__futex|futex|fsync|fdatasync|__lll|pthread_cond|__pthread|clock_nanosleep|epoll|poll|sched_yield)/ && f0 !~ /malloc|free|calloc|realloc|mem/) {
      st="wait:" f0
      for (i=1;i<ai;i++) { if (fname[i] ~ /futex_wait|lock_contended|wait_optional_timeout|wait<|sync_data|sync_all|write_all|pwrite|rename|open/) { st=st " <- " fname[i] "@" base(ffile[i]) ":" fline[i]; break } }
    }
    ph = (ai>0) ? fname[ai-1] "@" base(ffile[ai-1]) : "self"
    PS[ph " | " (st=="run" ? "run" : "wait")]++
    S[st]++
    if (st=="run") {
      runs++
      lf=""; for (i=0;i<ai;i++) { c=crate(fname[i],ffile[i]); if (c!="") { lf=c; break } }
      if (lf=="") lf="(std/core only) " fname[0]
      L[lf]++
      split("",seen); for (i=0;i<ai;i++) { c=crate(fname[i],ffile[i]); sub(/:.*/,"",c); if (c!="" && !(c in seen)) { seen[c]=1; I[c]++ } }
    }
  }
  inth=0; nf=0
}
/^==SAMPLE==/ { flush(); nsamp++; next }
/^Thread [0-9]+ / { flush(); inth=1; nf=0; next }
/^#[0-9]+ / { if (!inth) next; line=$0; sub(/^#[0-9]+ +(0x[0-9a-f]+ in )?/,"",line); fn=line; sub(/ \(.*$/,"",fn);
  file=""; ln=""; if (match(line,/ at [^ ]+$/)) { file=substr(line,RSTART+4); ln=file; sub(/^.*:/,"",ln) }
  fname[nf]=fn; ffile[nf]=file; fline[nf]=ln; nf++; next }
END {
  flush()
  printf "stack samples (all threads stopped): %d\nthread-samples with %s on stack: %d (run %d)\n", nsamp, anchor, total, runs
  print "\n# state"; for (k in S) printf "%7d  %s\n", S[k], k | "sort -rn"; close("sort -rn")
  print "\n# phase (callee under anchor) | run or wait"; for (k in PS) printf "%7d  %s\n", PS[k], k | "sort -rn"; close("sort -rn")
  print "\n# leaf (self) of run samples"; for (k in L) printf "%7d  %s\n", L[k], k | "sort -rn"; close("sort -rn")
  print "\n# inclusive crate presence in run samples"; for (k in I) printf "%7d  %s\n", I[k], k | "sort -rn"; close("sort -rn")
}' "$samples"
