from pathlib import Path
import json,os,subprocess,time,sys
h=Path.home();root=h/'workspace/hermes-loop-synapse105-L662';out=h/'handoffs/L662-initial-host'
if len(sys.argv)>1 and sys.argv[1]=='setup':
    if root.exists() or out.exists():raise SystemExit('Existing workspace/run: inspect rather than relaunch')
    root.parent.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True)
    subprocess.run(['git','clone','--no-checkout','https://github.com/aien-dev/synapse.git',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'fetch',str(h/'handoffs/L662-synapse105-initial.bundle'),'refs/heads/qualification/105-recovered'],check=True)
    subprocess.run(['git','-C',str(root),'switch','-c','qualification/105-recovered','FETCH_HEAD'],check=True)
    print('Prepared owned Linux checkout',root);raise SystemExit(0)
sha=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
assert subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True)==''
env=os.environ.copy();env['PATH']=str(h/'.cargo/bin')+':'+str(h/'.local/bin')+':'+env['PATH'];env['TMPDIR']=str(out/'tmp');env['CARGO_TARGET_DIR']=str(h/'workspace/targets/L662'/sha)
Path(env['TMPDIR']).mkdir(exist_ok=True)
state={'source':sha,'pid':os.getpid(),'started':time.time(),'status':'running','steps':[]};(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
commands=[('tools',['bash','-c','rustc -vV; cargo -V; uname -a']),('full-suite',['cargo','test','--locked','-j','6','--workspace','--no-fail-fast']),('repair',['cargo','test','--locked','-j','6','-p','synapse-store','r1_repair','--','--test-threads=1']),('repair-cli',['cargo','test','--locked','-j','6','-p','synapse-bench','--test','store_repair_cli']),('fmt',['cargo','fmt','--all','--check']),('clippy',['cargo','clippy','--locked','-j','6','--workspace','--all-targets','--','-D','warnings'])]
for name,cmd in commands:
    state['current']=name;(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    with (out/(name+'.log')).open('w') as log:
        actual=['timeout','--signal=TERM','20m',str(h/'.local/bin/quiet-build'),*cmd] if name!='tools' else cmd
        rc=subprocess.run(actual,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
    state['steps'].append({'step':name,'command':actual,'exit':rc});(out/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    if rc:
        state['status']='failed' if rc!=124 else 'incomplete_timeout';break
else:state['status']='passed'
state['finished']=time.time();state.pop('current',None);(out/'state.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(state,indent=2))
raise SystemExit(0 if state['status']=='passed' else 1)
