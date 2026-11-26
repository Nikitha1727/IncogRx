import argparse,base64,hashlib,json,os,re,subprocess,sys,tempfile,time,unicodedata,urllib.parse
from pathlib import Path

def norm(s): return unicodedata.normalize('NFKC',s).casefold().replace('\u200b','').translate(str.maketrans('०१२३४५६७८९','0123456789'))
def expand(s):
    parts=[s,urllib.parse.unquote(s)]
    for t in re.findall(r'[A-Za-z0-9+/=]{16,}',s):
        for f in (lambda:base64.b64decode(t,validate=True),lambda:bytes.fromhex(t)):
            try: parts.append(f().decode())
            except (ValueError,UnicodeError): pass
    return norm('\n'.join(parts))
def snap(p): return {str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(p.rglob('*')) if f.is_file()}
def scan(p,exclude=False): return '\n'.join(str(f.relative_to(p))+'\n'+f.read_bytes().decode(errors='replace') for f in p.rglob('*') if f.is_file() and not f.is_symlink() and not(exclude and f.relative_to(p).parts[0]=='quarantine'))
def main():
    a=argparse.ArgumentParser(); a.add_argument('--entry',required=True); a.add_argument('--validator',required=True); a.add_argument('--results',default='results.json'); a=a.parse_args(); entry=Path(a.entry).resolve(); validator=Path(a.validator).resolve()
    cases=json.loads(Path(__file__).with_name('fixtures.json').read_text())
    for kind,enc in [('base64',lambda s:base64.b64encode(s.encode()).decode()),('hex',lambda s:s.encode().hex()),('percent',lambda s:urllib.parse.quote(s,safe=''))]:
        number={'base64':'9000012350','hex':'9000012352','percent':'9000012353'}[kind]; t='Vritika Menon '+kind+' '+number; cases.append(dict(file=f'misc/{kind}.json',text=json.dumps({'attachment':enc(t),'clinical':'BP 120/80'}),remove=[t,number],keep=['BP 120/80']))
    cases.append(dict(file='misc/deep.json',text='['*1500+'"SYNTHCANARY_DEEP_93"'+']'*1500,remove=['SYNTHCANARY_DEEP_93'],quarantine=True))
    cases.append(dict(file='misc/binary.jpg',text='SYNTHCANARY_JPG_94',remove=['SYNTHCANARY_JPG_94'],quarantine=True))
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); inp=root/'input'; inp.mkdir()
        for c in cases:
            p=inp/c['file']; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(c['text'].encode(c.get('encoding','utf-8'))); c['sha']=hashlib.sha256(p.read_bytes()).hexdigest()
        original=snap(inp); runs=[]; snapshots=[]; ids=[]
        for i,key in enumerate(['phase5-test-A','phase5-test-A','phase5-test-B']):
            out=root/f'out{i}'; home=root/f'home{i}'; tmp=root/f'tmp{i}'
            for p in (out,home,tmp): p.mkdir()
            env=dict(os.environ,RAKSHA_SECRET=key,HOME=str(home),TMPDIR=str(tmp),RAKSHA_CPUS='2',OMP_NUM_THREADS='2',MKL_NUM_THREADS='2',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1'); start=time.monotonic()
            try:
                p=subprocess.run([sys.executable,str(entry),'--input',str(inp),'--output',str(out)],cwd=entry.parent,env=env,capture_output=True,timeout=900); rc=p.returncode; logs=(p.stdout+p.stderr).decode(errors='replace')
            except subprocess.TimeoutExpired: rc=-1; logs='timeout'
            elapsed=time.monotonic()-start; v=subprocess.run([sys.executable,str(validator),'--input',str(inp),'--output',str(out)],capture_output=True,timeout=60)
            try: report=json.loads((out/'report.json').read_text()); entries={x['input_sha256']:x for x in report['files']}
            except (OSError,ValueError,KeyError,TypeError): report={}; entries={}
            channels=expand(scan(out,True)+'\n'+logs+'\n'+scan(home)+'\n'+scan(tmp)); results=[]
            for j,c in enumerate(cases,1):
                e=entries.get(c['sha'],{}); rel=e.get('output'); p=out/rel if isinstance(rel,str) else None; content=p.read_text(errors='replace') if p and p.is_file() and p.resolve().is_relative_to(out.resolve()) else ''; errors=[]
                if c.get('quarantine'):
                    if e.get('status')!='quarantined' or rel is not None: errors.append('not safely quarantined')
                else:
                    if e.get('status')!='sanitized' or not content: errors.append('not exported')
                    if any(k not in content for k in c.get('keep',[])): errors.append('clinical probe lost')
                if any(norm(k) in channels for k in c.get('remove',[])): errors.append('PII leaked')
                results.append(dict(id=j,errors=errors))
            runs.append(dict(exit=rc,contract=v.returncode==0,seconds=round(elapsed,3),reported_peak_rss_mb=report.get('resources',{}).get('peak_rss_mb'),input_unchanged=snap(inp)==original,passed=sum(not x['errors'] for x in results),total=len(cases),cases=results,secret_leaked=norm(key) in channels))
            snapshots.append((snap(out/'sanitized'),snap(out).get('records.jsonl')))
            try: ids.append({x['patient'] for l in (out/'records.jsonl').read_text().splitlines() if (x:=json.loads(l)).get('patient')})
            except (OSError,ValueError): ids.append(set())
        summary=dict(runs=runs,same_secret_identical=snapshots[0]==snapshots[1],different_secret_nonempty_disjoint=bool(ids[0] and ids[2] and not ids[0]&ids[2]),pseudonym_counts=[len(x) for x in ids]); Path(a.results).write_text(json.dumps(summary,indent=2)); print(json.dumps(summary,indent=2))
if __name__=='__main__': main()
