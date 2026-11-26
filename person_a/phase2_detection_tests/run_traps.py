"""Run synthetic end-to-end regression fixtures against a local CLI pipeline."""
import argparse, base64, hashlib, json, os, re, subprocess, sys, tempfile, unicodedata
from pathlib import Path
from collections import Counter

def norm(s): return ' '.join(unicodedata.normalize('NFKC',s).casefold().split())
def expanded(s):
    extra=[]
    for m in re.finditer(r'[A-Za-z0-9+/]{24,}={0,2}',s):
        try: extra.append(base64.b64decode(m.group()+ '='*(-len(m.group())%4)).decode('utf-8'))
        except (ValueError,UnicodeError): pass
    return s+'\n'+'\n'.join(extra)

def main():
    p=argparse.ArgumentParser(); p.add_argument('--entry',type=Path,required=True); p.add_argument('--results',type=Path,required=True); a=p.parse_args(); entry=a.entry.resolve(); tests=json.loads(Path(__file__).with_name('trap_tests.json').read_text()); results=[]
    with tempfile.TemporaryDirectory(prefix='synthetic_qa_') as tmp:
        root=Path(tmp); inp=root/'input'; out=root/'output'; inp.mkdir(); out.mkdir(); hashes={}
        for t in tests:
            dest=inp/t['path']; dest.parent.mkdir(parents=True,exist_ok=True); raw=t['text'].encode(t['encoding']); dest.write_bytes(raw); hashes[t['id']]=hashlib.sha256(raw).hexdigest()
        env=dict(os.environ,RAKSHA_SECRET='phase2-synthetic-test-key'); env['TMPDIR']=str(root/'tmp'); env['HOME']=str(root/'home'); Path(env['TMPDIR']).mkdir(); Path(env['HOME']).mkdir()
        proc=subprocess.run([sys.executable,str(entry),'--input',str(inp),'--output',str(out)],cwd=entry.parent,env=env,capture_output=True,text=True,timeout=900)
        if proc.returncode: raise SystemExit(f'Pipeline failed with code {proc.returncode}; inspect locally without publishing raw logs.')
        report=json.loads((out/'report.json').read_text()); entries={e['input_sha256']:e for e in report['files']}; side=proc.stdout+'\n'+proc.stderr
        for path in [out/'report.json',out/'records.jsonl']:
            if path.is_file(): side+='\n'+path.read_text(encoding='utf-8')
        for folder in [out/'logs',root/'tmp',root/'home']:
            if folder.exists():
                for path in folder.rglob('*'):
                    if path.is_file() and not path.is_symlink(): side+='\n'+str(path.relative_to(folder))+'\n'+path.read_bytes().decode('utf-8',errors='replace')
        for t in tests:
            e=entries.get(hashes[t['id']],{}); rel=e.get('output'); errors=[]; content=''; dest=None
            if not e: errors.append('missing report entry')
            if rel:
                dest=(out/rel).resolve()
                if not dest.is_relative_to((out/'sanitized').resolve()) or not dest.is_file(): errors.append('invalid output path')
                else:
                    content=dest.read_text(encoding='utf-8')
                    if dest.suffix=='.json':
                        try: json.loads(content)
                        except ValueError: errors.append('invalid JSON')
            if t['quarantine']:
                if e.get('status')!='quarantined' or rel: errors.append('expected quarantine')
            else:
                if e.get('status')!='sanitized' or not rel: errors.append('expected sanitized output')
                for v in t['keep']:
                    if v not in content: errors.append('clinical text missing: '+v)
            for v in t['remove']:
                if norm(v) in norm(expanded(content)+'\n'+str(rel or '')): errors.append('PII visible: '+v)
                # Shared names can legitimately be preserved in other fixtures; only check unique test identifiers in side channels.
                if v.startswith('TEST-') and norm(v) in norm(expanded(side)): errors.append('side-channel identifier: '+v)
            if hashlib.sha256((inp/t['path']).read_bytes()).hexdigest()!=hashes[t['id']]: errors.append('input modified')
            results.append(dict(id=t['id'],group=t['group'],passed=not errors,errors=errors))
    stats={g:{'passed':sum(r['passed'] for r in results if r['group']==g),'total':sum(r['group']==g for r in results)} for g in sorted({r['group'] for r in results})}
    summary={'passed':sum(r['passed'] for r in results),'total':len(results),'groups':stats,'results':results}; a.results.parent.mkdir(parents=True,exist_ok=True); a.results.write_text(json.dumps(summary,ensure_ascii=False,indent=2)); print(json.dumps({k:v for k,v in summary.items() if k!='results'},indent=2)); return 0 if summary['passed']==summary['total'] else 1
if __name__=='__main__': sys.exit(main())
