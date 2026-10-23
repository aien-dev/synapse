from pathlib import Path
import os,json,subprocess,hashlib,time
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';out=h/'handoffs/L662-final-host';out.mkdir(exist_ok=False)
prior=json.loads((h/'handoffs/L662-postfix-host/state.json').read_text());assert prior['status']=='passed'
assert all(hashlib.sha256((root/f).read_bytes()).hexdigest()==s for f,s in prior['source_inputs'].items())
known=['crates/synapse-store/src/blockdev.rs','crates/synapse-store/src/blockdev/repair.rs','crates/synapse-store/src/blockdev_tests.rs']
assert sorted(subprocess.check_output(['git','-C',str(root),'diff','--name-only'],text=True).splitlines())==sorted(known)
# The only dirty bytes are the already archived/tested parent fixes, present in the bundle.
subprocess.run(['git','-C',str(root),'restore','--',*known],check=True)
subprocess.run(['git','-C',str(root),'fetch',str(h/'handoffs/L662-final-source.bundle'),'refs/heads/qualification/105-recovered'],check=True)
subprocess.run(['git','-C',str(root),'merge','--ff-only','FETCH_HEAD'],check=True)
sha=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip();assert sha=='0d95893afc6309dc280befe77806975734af8148'
assert subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)==''
paths=subprocess.check_output(['git','-C',str(root),'diff','--name-only','5b732e5d353bbcc3f6d0cd1eac60f2e543601521..HEAD','--','crates','Cargo.toml','Cargo.lock'],text=True).splitlines()
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');Path(env['TMPDIR']).mkdir();env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662'/sha)
env['SYNAPSE_H1_REAL_REPO']=str(root/'.git')
fixture_pin='1b6e340d48417dfbcfe2df56d48a0696a3a9b250'
for candidate in [h/'workspace/aien-sovereign-core',h/'workspace/pipeline/clones/aien-sovereign-core']:
    if candidate.exists() and subprocess.run(['git','-C',str(candidate),'cat-file','-e',fixture_pin+'^{commit}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
        env['C1_FIXTURE_REPO']=str(candidate)
        break
else:
    raise RuntimeError('Required immutable Gate4 fixture absent; no test waiver')
state={'source':sha,'pid':os.getpid(),'started':time.time(),'source_inputs':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in paths},'status':'running','steps':[]}
commands=[('full-suite',['cargo','test','--locked','-j','6','--workspace','--no-fail-fast']),('both-required-fixtures',['cargo','test','--locked','-j','6','--workspace','--','--ignored','--nocapture','--test-threads=1']),('repair-cli',['cargo','test','--locked','-j','6','-p','synapse-bench','--test','store_repair_cli']),('fmt',['cargo','fmt','--all','--check']),('clippy',['cargo','clippy','--locked','-j','6','--workspace','--all-targets','--','-D','warnings']),('pinned-crumb',[str(h/'workspace/hermes-L662-crumb12ad/tools/crumb/crumb'),'verify','.'])]
for name,cmd in commands:
    state['current']=name;(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');actual=['timeout','--signal=TERM','20m',str(h/'.local/bin/quiet-build'),*cmd]
    with (out/(name+'.log')).open('w') as f:rc=subprocess.run(actual,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    state['steps'].append({'step':name,'command':actual,'exit':rc});(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    if rc:state['status']='failed' if rc!=124 else 'incomplete_timeout';break
else:state['status']='passed'
state['finished']=time.time();state.pop('current',None);assert all(hashlib.sha256((root/f).read_bytes()).hexdigest()==s for f,s in state['source_inputs'].items());(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2));raise SystemExit(0 if state['status']=='passed' else 1)
