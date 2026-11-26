import unittest
from datetime import date
from privacy_reference import *

class PolicyTests(unittest.TestCase):
    def test_age_bounds(self):
        for age in range(126):
            for w in (5,10,20):
                lo,hi=map(int,age_band(age,w).split('-')); self.assertLessEqual(lo,age); self.assertGreaterEqual(hi,age)
    def test_date_interval(self):
        a,b='2024-02-25','2024-03-05'
        x,y=[date.fromisoformat(shift_date(v,'test','p1')) for v in (a,b)]
        self.assertEqual((y-x).days,9)
    def test_repeat(self):
        self.assertEqual(shift_date('2024-02-29','test','p1'),shift_date('2024-02-29','test','p1'))
    def test_key_rotation(self):
        self.assertGreater(sum(date_offset('a',str(i))!=date_offset('b',str(i)) for i in range(100)),95)
    def test_per_patient(self):
        offsets={date_offset('test',str(i)) for i in range(100)}; self.assertGreater(len(offsets),80); self.assertNotIn(0,offsets)
    def test_no_key(self):
        with self.assertRaises(ValueError): date_offset('','p1')
    def test_common_group(self):
        p=[dict(key=str(i),age=42,district='D',gender='F',conditions=['common']) for i in range(5)]
        self.assertTrue(all(x['level']==0 for x in plan(p).values()))
    def test_rare(self):
        p=[dict(key=str(i),age=42,district='D',gender='F',conditions=['common']) for i in range(5)]
        p[0]['conditions']=['rare']; self.assertTrue(plan(p)['0']['review_required'])
    def test_tiny_dataset(self):
        p=[dict(key='a',age=97,district='D',gender='F',conditions=['rare'])]
        x=plan(p)['a']; self.assertEqual(x['level'],3); self.assertTrue(x['review_required'])
    def test_duplicate(self):
        with self.assertRaises(ValueError): plan([{'key':'a'},{'key':'a'}])
    def test_order(self):
        p=[dict(key=str(i),age=40+i,district='D',gender='F',conditions=['common']) for i in range(10)]
        self.assertEqual(plan(p),plan(p[::-1]))
    def test_actual_group_counts(self):
        p=[dict(key=str(i),age=40+i,district='D',gender='F',conditions=['common']) for i in range(12)]
        d=plan(p); c=Counter((x['age_band'],x['district'],x['gender']) for x in d.values())
        for x in d.values(): self.assertEqual(x['group_size'],c[(x['age_band'],x['district'],x['gender'])])
if __name__=='__main__': unittest.main()
