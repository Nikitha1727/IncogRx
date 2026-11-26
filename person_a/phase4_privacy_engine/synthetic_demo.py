import json
from collections import Counter
from privacy_reference import plan, summarize, signature
profiles=[]
for i in range(30):
    profiles.append(dict(key=f'fixture-{i}',age=40+i%10 if i<20 else 72+i%10,district=['D1','D2','D3'][i%3],gender=['F','M'][i%2],conditions=['common' if i<27 else f'rare-{i}']))
sigs=[signature(p,0) for p in profiles]; counts=Counter(sigs)
before={'patients':len(profiles),'min_group_size':min(counts.values()),'unique_fraction':sum(counts[s]==1 for s in sigs)/len(sigs),'mean_inverse_group_size':sum(1/counts[s] for s in sigs)/len(sigs)}
decisions=plan(profiles)
print(json.dumps({'description':'Independent synthetic fixture; demographic proxy only, not official risk score','fixed_5_year_district_gender':before,'adaptive':summarize(decisions),'levels':dict(Counter(x['level'] for x in decisions.values()))},indent=2))
