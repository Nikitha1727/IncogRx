import argparse,json,os,sys,tempfile,subprocess,hashlib
from pathlib import Path
from fixtures import build

def check(inp,out,cases):
    report=json.loads((out/'report.json').read_text()); paths={r['input_sha256']:r.get('output') for r in report['files']}; records={}
    for l in (out/'records.jsonl').read_text().splitlines():
        r=json.loads(l); records[(r['file'],r['loc'])]=r.get('patient')
    def lookup(name):
        path=paths.get(hashlib.sha256((inp/name).read_bytes()).hexdigest()); p=out/path if path else None
        if not p or not p.is_file() or (path,'doc') not in records: return False,None
        y=records[path,'doc']; return (not y or y in p.read_text(encoding='utf-8')),y
    results=[]
    for c in cases:
        (ok1,a),(ok2,b)=map(lookup,c['files']); kind=c['expect']
        # Negative cases require both assigned to prevent vacuous success.
        passed=ok1 and ok2 and (bool(a and b and a==b) if kind=='same' else bool(a and b and a!=b) if kind=='different' else bool(a and b is None))
        results.append({'case':c['case'],'expect':kind,'passed':passed,'assigned':[bool(a),bool(b)]})
    return results
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--entry',type=Path,required=True);p.add_argument('--results',type=Path,required=True);a=p.parse_args();entry=a.entry.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        inp=Path(tmp)/'input';out=Path(tmp)/'output';cases=build(inp)
        env={**os.environ,'RAKSHA_SECRET':'phase3-synthetic-test-only'}
        r=subprocess.run([sys.executable,str(entry),'--input',str(inp),'--output',str(out)],cwd=entry.parent,env=env,capture_output=True,timeout=900)
        if r.returncode: raise SystemExit('Pipeline failed; inspect locally without logging sensitive data.')
        results=check(inp,out,cases)
    a.results.write_text(json.dumps(results,indent=2));print(f'{sum(x["passed"] for x in results)}/{len(results)} cases passed')
