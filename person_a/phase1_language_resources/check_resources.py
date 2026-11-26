import json,re
from pathlib import Path
p=Path(__file__).parent/'phase1'
d={f.stem:json.loads(f.read_text(encoding='utf-8')) for f in sorted(p.glob('*.json'))}
assert len(d)==6
for key in ('first_names','surnames'):
    assert all(x['latin'] and x['hindi'] for x in d[key]); print(key,len(d[key]))
assert len(d['context_rules']['digit_map'])==10
assert '९०१'.translate(str.maketrans(d['context_rules']['digit_map']))=='901'
patterns={k:re.compile(v) for k,v in d['clinical_keep']['clinical_patterns'].items()}
for k,s in [('dose','650mg'),('dose','1 g'),('dose','100/25 mg'),('schedule','1-0-1'),('duration','x 2 wks'),('duration','x 1 month'),('bp_candidate','BP 117/82'),('lab_candidate','180 mg/dL'),('loinc_candidate','718-7')]:
    assert patterns[k].search(s),(k,s)
print('variant groups',len(d['name_variants']['groups']))
print('drug entries',len(d['clinical_keep']['drugs']))
print('lab terms',len(d['clinical_keep']['lab_tests']))
print('RESOURCE CHECK OK — 6 JSON files; 9 regex examples')
