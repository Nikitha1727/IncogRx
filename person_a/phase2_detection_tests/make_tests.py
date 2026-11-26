import json, base64
from pathlib import Path
R=Path(__file__).resolve().parent
cases=[]
def add(group,text,remove=(),keep=(),filename=None,quarantine=False,encoding='utf-8'):
    n=len(cases)+1; cases.append(dict(id=f'T{n:03}',group=group,path=filename or f'notes/note_{n:03}.txt',text=text,remove=list(remove),keep=list(keep),quarantine=quarantine,encoding=encoding))
add('context','C/O Ramesh, H.No. 364, Ward 20',['Ramesh','H.No. 364','Ward 20'])
add('context','C/O fever and cough since 3 days',keep=['C/O fever and cough since 3 days'])
add('context','Reviewed by Dr. Ramesh',keep=['Reviewed by Dr. Ramesh'])
add('clinical','Dolo 650 1-0-1 x 5 days',keep=['Dolo 650 1-0-1 x 5 days'])
add('relative','S/o Zubair',['Zubair'])
add('clinical',"K/C/O addison's disease",keep=["K/C/O addison's disease"])
add('hinglish','Shahid sahab ka BP 117/82',['Shahid'],['BP 117/82'])
add('hindi','नाम: मोहम्मद शाहिद, 650mg 1-1-1 x 5 days',['मोहम्मद शाहिद'],['650mg 1-1-1 x 5 days'])
for text,rem,keep in [
('मरीज का नाम: देविका नायर\nबीपी 130/85',['देविका नायर'],['130/85']),('रोगी: नवनीत राव\nतापमान १०१°F',['नवनीत राव'],['१०१°F']),('नाम: इरफ़ान अंसारी\nमोबाइल: ९००००००००१',['इरफ़ान अंसारी','९००००००००१'],[]),('पति का नाम: हरीश वर्मा\nदवा: Metformin 500 mg',['हरीश वर्मा'],['Metformin 500 mg']),('ग्राम: काल्पनिकपुर\nपिन: १२३४५६\nHb 11.2 g/dL',['काल्पनिकपुर','१२३४५६'],['Hb 11.2 g/dL']),('आधार: XXXX XXXX 4321\nSpO2 98%',['XXXX XXXX 4321'],['SpO2 98%']),('नाम: काव्या मेहता\nशिकायत: बुखार और खांसी',['काव्या मेहता'],['बुखार और खांसी']),('रोगी की पुत्री: निधि राव\nPulse 72/min',['निधि राव'],['Pulse 72/min'])]: add('hindi',text,rem,keep)
for text,rem,keep in [('Devika ji ka sugar 180 mg/dL',['Devika'],['180 mg/dL']),('Navneet bhaiya ko bukhar 103 F',['Navneet'],['bukhar 103 F']),('Irfan saheb ki tabiyat theek hai; BP 120/80',['Irfan'],['BP 120/80']),('Patient ka naam Kavya Mehta; Dolo 650 BD',['Kavya Mehta'],['Dolo 650 BD']),('Pati ka naam Harish Verma; Hb 10.4 g/dL',['Harish Verma'],['Hb 10.4 g/dL']),('Nidhi didi ka pulse 80/min',['Nidhi'],['pulse 80/min']),('Patient ko raat mein neend nahi aayi',[],['Patient ko raat mein neend nahi aayi'])]: add('hinglish',text,rem,keep)
for text,rem,keep in [('Patient: Devika Nair\nMRN: TEST-MRN-9931\nBP 130/85',['Devika Nair','TEST-MRN-9931'],['BP 130/85']),('UHID: TEST-UH-2145\nTab Amlodipine 5 mg',['TEST-UH-2145'],['Tab Amlodipine 5 mg']),('Phone: +91 90000-00002\nHbA1c 6.4%',['90000-00002'],['HbA1c 6.4%']),('Aadhaar: XXXX-XXXX-4321\nRR 20/min',['XXXX-XXXX-4321'],['RR 20/min']),('Insurance ID: TEST-INS-4422\nDiagnosis: Asthma',['TEST-INS-4422'],['Diagnosis: Asthma']),('DOB: 14/03/1982\nCreatinine 1.2 mg/dL',['14/03/1982'],['Creatinine 1.2 mg/dL']),('PAN: ABCDE1234F\nDolo 650',['ABCDE1234F'],['Dolo 650']),('Email: synthetic@example.invalid\nTemp 98.6 F',['synthetic@example.invalid'],['Temp 98.6 F']),('W/o Harish Verma\nC/O headache',['Harish Verma'],['C/O headache']),('Address: H.No. 42, Imaginary Lane, PIN 123456\nWard 3 transfer',['H.No. 42','Imaginary Lane','123456'],['Ward 3 transfer'])]: add('identifier',text,rem,keep)
for text in ["Parkinson's disease", "Alzheimer’s disease", 'Dr. Devika reviewed the patient.', 'Ramipril 5 mg OD', 'Tab Pantoprazole 40 mg 1-0-0 x 1 month', 'Inj Ceftriaxone 1g IV x 2 wks', 'BP 150/90 mmHg; SpO2 97%; RR 18/min', 'HbA1c 7.2%; Creatinine 1.3 mg/dL', 'H/O diabetes; K/C/O hypertension', 'Tab Amlodipine 5 mg; 1-0-1; x 5 days', 'Sodium 138 mmol/L; Potassium 4.2 mmol/L', 'Transferred to ICU Ward 3', 'Dolo 650 BD x 5 days', 'C/O chest pain since 2 days']: add('clinical',text,keep=[text])
add('structured','Patient Name,MRN,BP\nDevika Nair,TEST-MRN-873,120/80\n',['Devika Nair','TEST-MRN-873'],['120/80'],filename='registration/example.csv')
add('structured','Naam\tMobile\tMedicine\nकाव्या मेहता\t९००००००००३\tDolo 650\n',['काव्या मेहता','९००००००००३'],['Dolo 650'],filename='registration/example.tsv',encoding='utf-16')
add('structured',json.dumps({'patient':{'name':'Navneet Rao','mrn':'TEST-JSON-33'},'bp':'118/79'}),['Navneet Rao','TEST-JSON-33'],['118/79'],filename='opd/nested.json')
add('hidden',json.dumps({'Devika Nair':{'BP':'122/81'}}),['Devika Nair'],['122/81'],filename='misc/key.json')
add('hidden','Devika Nair TEST-HDR-91,BP\n,120/80\n',['Devika Nair','TEST-HDR-91'],['120/80'],filename='misc/header.csv')
add('hidden','BP 121/80',['Devika_Nair','TEST-FILE-92'],['BP 121/80'],filename='misc/Devika_Nair_TEST-FILE-92.txt')
add('hidden',json.dumps({'metadata':{'source':'archive/Devika Nair/TEST-META-94.txt'},'bp':'125/80'}),['Devika Nair','TEST-META-94'],['125/80'],filename='misc/metadata.json')
add('hidden',json.dumps({'attachment':base64.b64encode(b'Patient: Devika Nair; MRN: TEST-B64-95').decode(),'bp':'123/80'}),['Devika Nair','TEST-B64-95'],['123/80'],filename='misc/attachment.json')
add('quarantine','{"patient":"Devika Nair",',['Devika Nair'],filename='misc/broken.json',quarantine=True)
add('quarantine','Patient: Devika Nair',['Devika Nair'],filename='misc/unsupported.xml',quarantine=True)
add('quarantine','',filename='misc/empty.txt',quarantine=True)
(R/'trap_tests.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2),encoding='utf-8'); print(len(cases))
