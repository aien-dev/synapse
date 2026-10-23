from pathlib import Path
import os,subprocess,json
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';out=h/'handoffs/L662-fixture-gates';out.mkdir(exist_ok=False)
post=json.loads((h/'handoffs/L662-postfix-host/state.json').read_text());assert post['status']=='passed'
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');Path(env['TMPDIR']).mkdir();env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662'/post['base_carry']);env['SYNAPSE_H1_REAL_REPO']=str(root/'.git')
pin='1b6e340d48417dfbcfe2df56d48a0696a3a9b250'
found=None
for p in [h/'workspace/aien-sovereign-core',h/'workspace/pipeline/clones/aien-sovereign-core']:
    if p.exists() and subprocess.run(['git','-C',str(p),'cat-file','-e',pin+'^{commit}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:found=p;break
state={'source_inputs':post['source_inputs'],'fixture_pin':pin,'results':[],'complete':False}
if found:env['C1_FIXTURE_REPO']=str(found)
for label,args in [('c1-fixture',['-p','synapse-bench','--test','c1_tree_parity','c1_tree_and_diff_parity_with_git_on_gate4_fixture']),('h1-real-repository',['-p','synapse-git','--test','h1_git_bridge','h1_real_repository_full_history_round_trips_with_identical_object_ids'])]:
    if label=='c1-fixture' and not found:
        state['results'].append({'gate':label,'status':'NOT_RUN','reason':'immutable required Gate4 fixture commit absent from checked existing clones'});continue
    cmd=['timeout','--signal=TERM','20m',str(h/'.local/bin/quiet-build'),'cargo','test','--locked','-j','6',*args,'--','--ignored','--nocapture','--test-threads=1']
    with (out/(label+'.log')).open('w') as f:rc=subprocess.run(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    state['results'].append({'gate':label,'command':cmd,'exit':rc,'status':'PASS' if rc==0 else 'FAIL'});print(label,'exit',rc);print('\n'.join((out/(label+'.log')).read_text().splitlines()[-14:]));(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
state['complete']=all(r['status']=='PASS' for r in state['results']);(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2));raise SystemExit(0 if state['complete'] else 1)
