from pathlib import Path
import os,json,subprocess,hashlib,time
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';out=h/'handoffs/L662-review-fix';out.mkdir(exist_ok=False)
red=json.loads((h/'handoffs/L662-relative-backup-red/result.json').read_text());assert red['test_exit']==0 and red['backup_file_synced'] and not red['containing_directory_synced']
(root/'crates/synapse-store/src/blockdev/repair.rs').write_bytes((h/'handoffs/L662-relative-backup-green-repair.rs').read_bytes())
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');Path(env['TMPDIR']).mkdir();env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662/0d95893afc6309dc280befe77806975734af8148');env['SYNAPSE_H1_REAL_REPO']=str(root/'.git')
pin='1b6e340d48417dfbcfe2df56d48a0696a3a9b250'
for fixture in [h/'workspace/aien-sovereign-core',h/'workspace/pipeline/clones/aien-sovereign-core']:
    if fixture.exists() and subprocess.run(['git','-C',str(fixture),'cat-file','-e',pin+'^{commit}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:env['C1_FIXTURE_REPO']=str(fixture);break
else:raise RuntimeError('Required fixture absent')
paths=subprocess.check_output(['git','-C',str(root),'diff','--name-only','5b732e5d353bbcc3f6d0cd1eac60f2e543601521','--','crates','Cargo.toml','Cargo.lock'],text=True).splitlines()
state={'source_head':subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),'source_inputs':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in paths},'status':'running','steps':[],'pid':os.getpid(),'started':time.time()}
commands=[('relative-trace-green',['python3',str(h/'handoffs/L662-relative-backup-qualify.py'),'--root',str(root),'--out',str(h/'handoffs/L662-relative-backup-green')]),('full-suite',['cargo','test','--locked','-j','6','--workspace','--no-fail-fast']),('both-required-fixtures',['cargo','test','--locked','-j','6','--workspace','--','--ignored','--nocapture','--test-threads=1']),('repair-cli',['cargo','test','--locked','-j','6','-p','synapse-bench','--test','store_repair_cli']),('fmt',['cargo','fmt','--all','--check']),('clippy',['cargo','clippy','--locked','-j','6','--workspace','--all-targets','--','-D','warnings']),('pinned-crumb',[str(h/'workspace/hermes-L662-crumb12ad/tools/crumb/crumb'),'verify','.'])]
for name,cmd in commands:
    state['current']=name;(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');actual=['timeout','--signal=TERM','20m',str(h/'.local/bin/quiet-build'),*cmd]
    with (out/(name+'.log')).open('w') as f:rc=subprocess.run(actual,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    state['steps'].append({'step':name,'command':actual,'exit':rc});(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    if rc:state['status']='failed' if rc!=124 else 'incomplete_timeout';break
else:state['status']='passed'
state['finished']=time.time();state.pop('current',None);assert all(hashlib.sha256((root/f).read_bytes()).hexdigest()==s for f,s in state['source_inputs'].items());(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2));raise SystemExit(0 if state['status']=='passed' else 1)
