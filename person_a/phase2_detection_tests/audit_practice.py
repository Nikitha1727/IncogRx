"""Development-only audit. Never include truth or audit outputs in the submission release."""
import argparse, csv, json, sys
from pathlib import Path
from collections import Counter
p=argparse.ArgumentParser(); p.add_argument('--toolkit',type=Path,required=True); p.add_argument('--output',type=Path,required=True); p.add_argument('--audit',type=Path,required=True); a=p.parse_args()
sys.path.insert(0,str(a.toolkit.resolve())); from check_dev import norm, read_text, all_text_under
truth=json.loads((a.toolkit/'dev/truth/truth.json').read_text()); report=json.loads((a.output/'report.json').read_text()); renamed={e['input_sha256']:e.get('output') for e in report['files']}; a.audit.mkdir(parents=True,exist_ok=True)
leaks=[]; lost=[]; absent=[]; total=0; probes=0; whole=all_text_under(a.output); canaries=set()
for rel,f in truth['files'].items():
    mapped=renamed.get(f['sha256']); out_rel=mapped.removeprefix('sanitized/') if mapped else rel; path=a.output/'sanitized'/out_rel; exists=path.is_file(); content=norm(read_text(path)) if exists else ''; fname=norm(out_rel)
    for loc,u in f['units'].items():
        for e in u['entities']:
            s=norm(e['surface']); kind=e['type']
            if kind=='CANARY':
                if s and s in whole: canaries.add(s)
                continue
            total+=1
            if s and (s in fname if e['channel']=='filename' else exists and s in content):
                leaks.append(dict(file=rel,loc=loc,type=kind,language=e['script'],channel=e['channel'],surface=e['surface']))
        for v in u.get('preserve',[]):
            row=dict(file=rel,loc=loc,expected=v['text'])
            if not exists: absent.append(row)
            else:
                probes+=1
                if norm(v['text']) not in content: lost.append(row)
for name,rows,fields in [('leaks',leaks,['file','loc','type','language','channel','surface']),('lost_clinical',lost,['file','loc','expected']),('unexported_clinical',absent,['file','loc','expected'])]:
    with (a.audit/(name+'.csv')).open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
summary=dict(leaks=len(leaks),total=total,canaries=len(canaries),clinical_probes=probes,clinical_lost=len(lost),clinical_unexported=len(absent),by_type=dict(Counter(x['type'] for x in leaks)),by_language=dict(Counter(x['language'] for x in leaks)),by_channel=dict(Counter(x['channel'] for x in leaks)))
(a.audit/'summary.json').write_text(json.dumps(summary,indent=2)); print(json.dumps(summary,indent=2))
