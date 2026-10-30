from pathlib import Path
import os,json,subprocess,hashlib
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';prior=h/'handoffs/L662-initial-host';out=h/'handoffs/L662-behavioral-red'
assert json.loads((prior/'state.json').read_text())['status']=='passed'
assert subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)==''
out.mkdir(exist_ok=False)
src=h/'handoffs/L662-blockdev-tests-red.rs';dst=root/'crates/synapse-store/src/blockdev_tests.rs';dst.write_bytes(src.read_bytes())
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');Path(env['TMPDIR']).mkdir();head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip();env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662'/head)
state={'production_head':head,'test_source_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'results':[],'complete':False}
for label,test,needle in [('backup-overflow','r1_repair_backup_overflow_length_is_refused_without_panicking','attempt to add with overflow'),('inherited-lock','r1_repair_parent_drop_releases_lock_despite_inherited_helper_fd',"retained the departed owner's lock")]:
    cmd=['timeout','--signal=TERM','120s',str(h/'.local/bin/quiet-build'),'cargo','test','--locked','-j','6','-p','synapse-store',test,'--','--nocapture','--test-threads=1']
    with (out/(label+'.log')).open('w') as f:rc=subprocess.run(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    text=(out/(label+'.log')).read_text();observed=rc==101 and needle in text
    state['results'].append({'case':label,'command':cmd,'exit':rc,'expected_behavior_failure_observed':observed});(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    print(label,'exit',rc,'behavioral RED',observed);print('\n'.join(text.splitlines()[-18:]))
state['complete']=all(x['expected_behavior_failure_observed'] for x in state['results']);(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
raise SystemExit(0 if state['complete'] else 1)
