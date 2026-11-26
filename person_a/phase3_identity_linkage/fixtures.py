import json,csv
from pathlib import Path
# Independent synthetic identities; no practice truth used.
CASES=[
('cross_script','same','Name: Naved Qureshi\nPhone: 9000000101\nDOB: 1988-02-03','नाम: नावेद कुरैशी\nमोबाइल: ९००००००१०१\nजन्म तिथि: 03/02/1988'),
('honorific','same','Patient: Kavya Menon\nPhone: 9000000102','Kavya ji ka BP 120/80\nMobile: +91 90000 00102'),
('abbreviation','same','Patient: Mohammad Zahir\nDOB: 1980-05-06\nMobile: 9000000103','Patient: Md. Zahir\nDOB: 06/05/1980\nPhone: 09000000103'),
('surname_first','same','Patient: Nitin Batra\nDOB: 1978-03-04\nPhone: 9000000104','Name: Batra, Nitin\nDOB: 04/03/1978\nMobile: 9000000104'),
('local_id','same','Hospital: Alpha\nUHID: AL-000105\nName: Tanu Sethi','Hospital: Alpha\nUHID: AL-000105\nBP 130/85'),
('fragmented','same','Name: Ira Kulkarni\nW/o: Nilesh Kulkarni\nDOB: 1990-08-09\nVillage: Testpur','Ira W/o Nilesh Kulkarni\nDOB: 09/08/1990\nVillage: Testpur'),
('homonym','different','Name: Neel Joshi\nDOB: 1981-01-01\nPhone: 9000000106','Name: Neel Joshi\nDOB: 1997-07-07\nPhone: 9000000107'),
('shared_phone','different','Name: Aditi Rao\nDOB: 1975-03-02\nPhone: 9000000108','Name: Rohan Rao\nDOB: 2002-04-03\nPhone: 9000000108'),
('hospital_namespace','different','Hospital: Alpha\nMRN: 100109\nName: Nisha Pal\nDOB: 1994-01-02','Hospital: Beta\nMRN: 100109\nName: Kunal Das\nDOB: 1984-02-03'),
('relative_not_patient','different','Patient: Amrita Sen\nW/o: Deepak Sen\nPhone: 9000000110','Patient: Deepak Sen\nDOB: 1982-08-09\nPhone: 9000000111'),
('doctor_not_patient','different','Patient: Veena Lal\nReviewed by Dr. Ajay Lal\nPhone: 9000000112','Patient: Ajay Lal\nPhone: 9000000113'),
('weak_name','abstain','Patient: Pooja\nPhone: 9000000114','Pooja ji ka BP 117/82'),
('transitive_conflict','different','Name: Harish Dutt\nDOB: 1970-02-01\nPhone: 9000000115','Name: Harish Dutt\nDOB: 1990-02-01\nPhone: 9000000116'),
('changed_phone','same','Name: Ritu Bose\nDOB: 1989-03-01\nHospital: Beta\nUHID: BE-000117\nPhone: 9000000117','Name: Ritu Bose\nDOB: 1989-03-01\nHospital: Beta\nUHID: BE-000117\nPhone: 9000000118'),
('initials','same','Name: Suresh Krishnan\nDOB: 1986-11-12\nPhone: 9000000119','Name: S. Krishnan\nDOB: 12/11/1986\nPhone: 9000000119'),
('cross_hospital','same','Hospital: Alpha\nUHID: AL-000120\nName: Tanvi Bedi\nDOB: 1991-03-04\nPhone: 9000000120','Hospital: Beta\nMRN: BE-000121\nName: Tanvi Bedi\nDOB: 04/03/1991\nPhone: 9000000120'),
]
def build(root):
    root.mkdir(parents=True,exist_ok=True); expected=[]
    for name,kind,a,b in CASES:
        paths=[f'{name}_a.txt',f'{name}_b.txt']
        for p,t in zip(paths,[a,b]): (root/p).write_text(t+'\n',encoding='utf-8')
        expected.append(dict(case=name,expect=kind,files=paths))
    # Bridge record may attach to at most one of two conflicting identities.
    (root/'transitive_conflict_bridge.txt').write_text('Name: Harish Dutt\nPhone: 9000000115\nAlternate phone: 9000000116\n',encoding='utf-8')
    return expected
if __name__=='__main__':
    import sys
    root=Path(sys.argv[1]); print(json.dumps(build(root),indent=2))
