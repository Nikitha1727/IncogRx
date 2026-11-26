"""Usage: python3 benchmarks/bench.py <repo_dir> <label> <out.json> name=/path/to/input [name=/path ...]
Runs main.py twice per dataset (RAKSHA_SECRET=bench) and records wall time, peak RSS and counts."""
import json,subprocess,sys,time,os,platform,shutil,tempfile
from pathlib import Path
eng=Path(sys.argv[1]); label=sys.argv[2]; out=sys.argv[3]
sets=dict(a.split("=",1) for a in sys.argv[4:])
res={"engine":label,"python":platform.python_version(),"machine":platform.machine(),"runs":{}}
for n,d in sets.items():
    files=sum(1 for p in Path(d).rglob('*') if p.is_file()); size=sum(p.stat().st_size for p in Path(d).rglob('*') if p.is_file())
    times=[]
    for i in range(2):
        o=os.path.join(tempfile.gettempdir(),"bench_out"); shutil.rmtree(o,ignore_errors=True)
        s=time.monotonic(); r=subprocess.run([sys.executable,"main.py","--input",d,"--output",o],cwd=eng,env=dict(os.environ,RAKSHA_SECRET="bench"),capture_output=True); times.append(round(time.monotonic()-s,2))
        rep=json.load(open(o+"/report.json"))
    res["runs"][n]={"files":files,"bytes":size,"wall_seconds":times,"best_wall_seconds":min(times),"peak_rss_mb":rep.get("resources",{}).get("peak_rss_mb"),"exit":r.returncode,
                    "counts":rep.get("counts")}
json.dump(res,open(out,"w"),indent=2); print(json.dumps({k:(v["best_wall_seconds"],v["peak_rss_mb"]) for k,v in res["runs"].items()}))
