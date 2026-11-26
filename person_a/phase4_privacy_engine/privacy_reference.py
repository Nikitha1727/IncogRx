"""Reference policy for normalized patient profiles; not a file sanitizer."""
import hashlib
import hmac
from collections import Counter
from datetime import date, timedelta
import json
from pathlib import Path

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())

def keyed_digest(secret, domain, key):
    if not secret or not key:
        raise ValueError('missing_key_material')
    return hmac.new(secret.encode(), (domain+'\0'+key).encode(), hashlib.sha256).digest()

def date_offset(secret, cluster_key):
    limit = POLICY['date_shift_max_days']
    n = int.from_bytes(keyed_digest(secret, 'raksha/date/v1', cluster_key), 'big') % (2*limit)
    return n-limit if n < limit else n-limit+1

def shift_date(value, secret, cluster_key):
    return (date.fromisoformat(value)+timedelta(days=date_offset(secret, cluster_key))).isoformat()

def age_band(age, width):
    if age is None: return None
    if not isinstance(age, int) or isinstance(age, bool) or not 0 <= age <= 125:
        raise ValueError('invalid_age')
    lo = age//width*width
    return f'{lo}-{lo+width-1}'

def signature(profile, level):
    # Only a conservative subset of profile-level quasi-identifiers.
    age = age_band(profile.get('age'), [5,10,20][level]) if level < 3 else None
    return (age, profile.get('district') if level == 0 else None,
            profile.get('gender') if level < 2 else None)

def plan(profiles, k=None):
    """One normalized profile per distinct patient. Never export cluster keys.
    Output is an INTERNAL decision map, not a released artifact.
    Missing fields must be represented by None. Conditions are normalized codes.
    """
    k = POLICY['target_k'] if k is None else k
    if k < 2: raise ValueError('invalid_k')
    by_id = {p['key']: p for p in profiles}
    if len(by_id) != len(profiles): raise ValueError('duplicate_profile')
    counts = Counter(c for p in profiles for c in set(p.get('conditions', [])))
    rare = {key: any(counts[c] <= POLICY['rare_condition_max_patients'] for c in p.get('conditions', [])) for key,p in by_id.items()}
    levels = {key: 2 if rare[key] else 0 for key in by_id}
    while True:
        sigs = {key: signature(p, levels[key]) for key,p in by_id.items()}
        sizes = Counter(sigs.values())
        promote = [key for key in by_id if sizes[sigs[key]] < k and levels[key] < 3]
        if not promote: break
        for key in promote: levels[key] += 1
    result = {}
    for key,p in by_id.items():
        age,district,gender = sigs[key]
        result[key] = dict(age_band=age, district=district, gender=gender,
            level=levels[key], group_size=sizes[sigs[key]], rare_condition=rare[key],
            review_required=rare[key] or sizes[sigs[key]] < k)
    return result

def summarize(decisions):
    n = len(decisions)
    sizes = [x['group_size'] for x in decisions.values()]
    return {'patients':n, 'min_group_size':min(sizes, default=0),
            'mean_inverse_group_size':sum(1/s for s in sizes)/n if n else None,
            'unique_fraction':sum(s==1 for s in sizes)/n if n else None,
            'below_target_k':sum(s<POLICY['target_k'] for s in sizes),
            'rare_condition_profiles':sum(x['rare_condition'] for x in decisions.values()),
            'review_required':sum(x['review_required'] for x in decisions.values())}
