import argparse,json,collections,itertools
from pathlib import Path

def audit(toolkit, output):
    truth=json.loads((toolkit/'dev/truth/truth.json').read_text())
    report=json.loads((output/'report.json').read_text())
    paths={r['input_sha256']:r.get('output') for r in report['files']}
    records={}; duplicates=0
    for line in (output/'records.jsonl').read_text().splitlines():
        r=json.loads(line); k=(r['file'],r['loc']); duplicates+=k in records; records[k]=r.get('patient')
    units=[]; ambiguous=0
    for rel,f in truth['files'].items():
        path=paths.get(f['sha256']);
        for loc,u in f['units'].items():
            if u.get('link') not in ('required','ambiguous'): continue
            y=records.get((path,loc)) if path else None
            # Match the practice checker's JSON ancestor / doc fallback.
            if path and (path,loc) not in records:
                parts=loc.split('/')
                for i in range(len(parts)-1,1,-1):
                    k=(path,'/'.join(parts[:i]))
                    if k in records: y=records[k]; break
                else: y=records.get((path,'doc'))
            if u['link']=='ambiguous': ambiguous+=bool(y)
            else: units.append((u['patient'],y,rel,loc))
    groups=collections.defaultdict(list); pred=collections.defaultdict(list)
    for i,(t,y,*_) in enumerate(units):
        groups[t].append(i)
        if y: pred[y].append(i)
    pairs=lambda n:n*(n-1)//2
    tp=sum(sum(pairs(n) for n in collections.Counter(units[i][0] for i in v).values()) for v in pred.values())
    fp=sum(pairs(len(v)) for v in pred.values())-tp; fn=sum(pairs(len(v)) for v in groups.values())-tp
    p=tp/(tp+fp) if tp+fp else 0; r=tp/(tp+fn) if tp+fn else 0
    def trap(ids):
        total=good=0
        for t in ids:
            for i,j in itertools.combinations(groups[t],2):
                total+=1; good+=bool(units[i][1] and units[i][1]==units[j][1])
        return {'correct_pairs':good,'total_pairs':total}
    details=[]
    for v in pred.values():
        if len({units[i][0] for i in v})>1:
            details.append({'kind':'false_merge','records':[{'file':units[i][2],'loc':units[i][3]} for i in v]})
    for t,v in groups.items():
        if len({units[i][1] for i in v})>1 or any(not units[i][1] for i in v):
            details.append({'kind':'missed_link_or_unassigned','records':[{'file':units[i][2],'loc':units[i][3]} for i in v]})
    return {'required_units':len(units),'assigned':sum(bool(u[1]) for u in units),'ambiguous_assigned':ambiguous,'duplicate_locators':duplicates,'tp':tp,'fp':fp,'fn':fn,'precision':p,'recall':r,'f05':1.25*p*r/(.25*p+r) if p+r else 0,'merged_clusters':sum(d['kind']=='false_merge' for d in details),'language':trap(truth['traps']['language']),'fragmented':trap(truth['traps']['fragmented']),'homonym_pairs_with_shared_id':sum(bool({units[i][1] for i in groups[a] if units[i][1]} & {units[i][1] for i in groups[b] if units[i][1]}) for a,b in truth['traps']['homonym_pairs']),'details':details}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--toolkit',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--results',type=Path,required=True);a=p.parse_args(); result=audit(a.toolkit,a.output);a.results.write_text(json.dumps(result,ensure_ascii=False,indent=2)); print(json.dumps({k:v for k,v in result.items() if k!='details'},indent=2))
