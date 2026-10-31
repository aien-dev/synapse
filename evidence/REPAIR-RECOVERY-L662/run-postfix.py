from pathlib import Path
import os,json,subprocess,hashlib,time
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';out=h/'handoffs/L662-postfix-host'
assert json.loads((h/'handoffs/L662-behavioral-red/state.json').read_text())['complete']
expected=['crates/synapse-store/src/blockdev.rs','crates/synapse-store/src/blockdev/repair.rs','crates/synapse-store/src/blockdev_tests.rs']
dirty=subprocess.check_output(['git','-C',str(root),'diff','--name-only'],text=True).splitlines()
assert dirty==['crates/synapse-store/src/blockdev_tests.rs'],dirty
out.mkdir(exist_ok=False)
for relative,name in zip(expected,['L662-green-blockdev.rs','L662-green-repair.rs','L662-green-tests.rs']):(root/relative).write_bytes((h/'handoffs'/name).read_bytes())
head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');Path(env['TMPDIR']).mkdir();env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662'/head)
state={'base_carry':head,'source_inputs':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in expected},'pid':os.getpid(),'started':time.time(),'status':'running','steps':[]}
commands=[('focused-green',['cargo','test','--locked','-j','6','-p','synapse-store','r1_repair','--','--test-threads=1']),('full-suite',['cargo','test','--locked','-j','6','--workspace','--no-fail-fast']),('repair-cli',['cargo','test','--locked','-j','6','-p','synapse-bench','--test','store_repair_cli']),('fmt',['cargo','fmt','--all','--check']),('clippy',['cargo','clippy','--locked','-j','6','--workspace','--all-targets','--','-D','warnings'])]
for name,cmd in commands:
    state['current']=name;(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');actual=['timeout','--signal=TERM','20m',str(h/'.local/bin/quiet-build'),*cmd]
    with (out/(name+'.log')).open('w') as f:rc=subprocess.run(actual,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    state['steps'].append({'step':name,'command':actual,'exit':rc});(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    if rc:state['status']='failed' if rc!=124 else 'incomplete_timeout';break
else:state['status']='passed'
state['finished']=time.time();state.pop('current',None);assert all(hashlib.sha256((root/f).read_bytes()).hexdigest()==s for f,s in state['source_inputs'].items());(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2));raise SystemExit(0 if state['status']=='passed' else 1)
