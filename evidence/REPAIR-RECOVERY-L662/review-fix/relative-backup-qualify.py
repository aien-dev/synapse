"""Observe real file and directory fsync calls for a bare relative repair backup.
Requires Linux strace; uses only a synthetic in-memory device and owned scratch.
This is syscall-order coverage, not a physical crash/power-loss experiment.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
root=args.root.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
cwd=out/'cwd';cwd.mkdir();tmp=out/'tmp';tmp.mkdir();env=os.environ.copy();env['TMPDIR']=str(tmp);env.setdefault('CARGO_TARGET_DIR',str(out/'cargo'))
source_files=['crates/synapse-store/src/blockdev/repair.rs','crates/synapse-store/src/blockdev_tests.rs']
state={'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'inputs':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in source_files},'passed':False,'physical_crash_tested':False}
cmd=['cargo','test','--locked','-j','6','-p','synapse-store','--lib','--no-run','--message-format=json']
with (out/'build-json.log').open('w') as stdout,(out/'build-stderr.log').open('w') as stderr:
    result=subprocess.run(cmd,cwd=root,env=env,stdout=stdout,stderr=stderr,timeout=600)
if result.returncode:raise RuntimeError('Failed to build actual unit-test binary')
executables=[]
for line in (out/'build-json.log').read_text().splitlines():
    try:row=json.loads(line)
    except ValueError:continue
    if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='synapse_store' and row.get('profile',{}).get('test') and row.get('executable'):executables.append(row['executable'])
if len(set(executables))!=1:raise RuntimeError('Cannot uniquely bind actual synapse-store test binary')
binary=Path(executables[-1]);state['binary']=str(binary);state['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
test='blockdev_tests::repair_tests::r1_repair_bare_relative_backup_is_created_and_verified'
command=['strace','-f','-yy','-o',str(out/'trace.log'),'-e','trace=openat,fsync',str(binary),'--exact',test,'--nocapture','--test-threads=1']
with (out/'test.log').open('w') as log:rc=subprocess.run(command,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120).returncode
state['command']=command;state['test_exit']=rc
calls=[]
for index,line in enumerate((out/'trace.log').read_text().splitlines()):
    match=re.search(r'fsync\(\d+<([^>]+)>\)\s*=\s*0',line)
    if match:calls.append({'line':index,'path':match.group(1),'raw':line})
files=[c for c in calls if Path(c['path']).parent==cwd and Path(c['path']).name.startswith('relative-repair-backup-')]
dirs=[c for c in calls if Path(c['path'])==cwd]
state['successful_fsync_calls']=calls;state['backup_file_synced']=bool(files);state['containing_directory_synced']=bool(dirs)
state['passed']=rc==0 and bool(files) and bool(dirs) and files[0]['line']<dirs[0]['line']
(out/'result.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2))
raise SystemExit(0 if state['passed'] else 1)
