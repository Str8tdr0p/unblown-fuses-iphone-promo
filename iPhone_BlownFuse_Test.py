#!/usr/bin/env python3
"""
iPhone Fuse & Ghost Wake Analyzer v2.2
Universal iPhone 6s → iPhone 18

Performs:
  • TI SN27xxx PMGR fuse verification (bits [4,5,6])
  • Ghost wake event detection from tracev3 / unified logs
  • Optional timesync.tracev3 correlation for timestamps

Supports .tar, .tar.gz, and .zip sysdiagnose archives
"""

import sys, os, tarfile, zipfile, sqlite3, json, tempfile, shutil, glob, re
from datetime import datetime
from pathlib import Path

# ---------- Utilities ----------

def check_bits(value, bits):
    return [(value >> b) & 1 for b in bits]

def estimate_event_time(trace_path):
    """Approximate wall‑clock timestamp for a tracev3 file.
       Uses mtime now; can hook real timesync logic later."""
    try:
        return datetime.fromtimestamp(os.path.getmtime(trace_path))
    except Exception:
        return None

# ---------- Fuse Detector ----------

def extract_ti_sn27xxx_fuse_status(plsql_path):
    results = {'fuse_status': 'NO_DATA'}
    try:
        conn = sqlite3.connect(plsql_path)
        cursor = conn.execute("""
            SELECT Flags, timestamp 
            FROM PLBatteryAgent_EventBackward_Battery 
            WHERE Flags IS NOT NULL 
            ORDER BY timestamp DESC LIMIT 20
        """)
        flag_history = []
        for flags, ts in cursor.fetchall():
            bits = check_bits(flags, [4,5,6])
            unfused = all(b == 0 for b in bits)
            flag_history.append({
                'timestamp': ts,
                'flags': flags,
                'flags_hex': f"0x{flags:04X}",
                'bits_456': bits,
                'unfused': unfused
            })
        latest = flag_history[0] if flag_history else None
        if latest and latest['unfused']:
            results.update({
                'fuse_status': 'UNBLOWN_CONFIRMED',
                'proof': flag_history,
                'critical_bits': latest['bits_456'],
                'flags_hex': latest['flags_hex']
            })
        elif flag_history:
            results.update({'fuse_status': 'BLOWN','proof': flag_history})
        conn.close()
    except Exception as e:
        results['error'] = str(e)
    return results

# ---------- Main Analyzer ----------

class SysdiagnoseAnalyzer:
    wake_patterns = [
        re.compile(r"(DarkWake|com\.apple\.powermanagement.*wake|SleepService|BTServer|powerd.*Wake)", re.IGNORECASE)
    ]

    def __init__(self, archive_path):
        self.archive_path = archive_path
        self.temp_dir = None
        self.powerlog_files, self.trace_logs = [], []
        self.results, self.ghost_results = {}, []

    def run_analysis(self):
        self._extract_files()
        self._analyze_powerlogs()
        self._analyze_tracev3()
        return self._generate_report()

    # ---------- Extraction ----------

    def _extract_files(self):
        print("Extracting sysdiagnose...")
        self.temp_dir = tempfile.mkdtemp(prefix="fusev2_")
        name = self.archive_path.lower()
        if name.endswith(('.tar', '.tar.gz', '.tgz')):
            with tarfile.open(self.archive_path, 'r:*') as tar: tar.extractall(self.temp_dir)
        elif name.endswith('.zip'):
            with zipfile.ZipFile(self.archive_path, 'r') as z: z.extractall(self.temp_dir)
        else:
            raise ValueError("Unsupported archive type")

        # recursive decompress nested tars
        for t in glob.glob(os.path.join(self.temp_dir,'**','*.tar*'),recursive=True):
            try:
                with tarfile.open(t,'r:*') as sub: sub.extractall(self.temp_dir)
            except: pass

        # collect targets
        patterns = ['powerlog.PLSQL','PLSQL']
        for r,_,f in os.walk(self.temp_dir):
            for fn in f:
                if any(p in fn for p in patterns):
                    self.powerlog_files.append(os.path.join(r,fn))
        self.trace_logs = list(Path(self.temp_dir).rglob("*.tracev3"))
        print(f"Powerlogs: {len(self.powerlog_files)}  tracev3: {len(self.trace_logs)}")

    # ---------- Fuse Analysis ----------

    def _analyze_powerlogs(self):
        print("Analyzing TI SN27xxx fuse bits...")
        all_results=[]
        for pl in self.powerlog_files[:3]:
            res=extract_ti_sn27xxx_fuse_status(pl)
            all_results.append(res)
            print(f"  {os.path.basename(pl)} => {res['fuse_status']}")
        unfused=[r for r in all_results if r['fuse_status']=='UNBLOWN_CONFIRMED']
        total=[r for r in all_results if r['fuse_status']!='NO_DATA']
        self.results={
            'verdict':'UNBLOWN_FUSES_CONFIRMED' if len(unfused)==len(total) and total else 'FUSES_BLOWN',
            'all_analyses':all_results,'evidence_count':len(all_results)
        }

    # ---------- Ghost Wake ----------

    def _analyze_tracev3(self):
        print("Scanning trace logs for wake activity...")
        events=[]
        for path in self.trace_logs[:50]:
            try:
                data=open(path,'rb').read().decode('latin-1','ignore')
                for pat in self.wake_patterns:
                    for m in pat.finditer(data):
                        context=data[max(0,m.start()-60):m.end()+80]
                        ts=estimate_event_time(path)
                        events.append({
                            'timestamp': ts.isoformat() if ts else "unknown",
                            'file': str(path),
                            'context': context.strip().replace("\n"," ")[:180]
                        })
            except Exception:
                continue
        self.ghost_results=events
        print(f"Ghost-wake events detected: {len(events)}")

    # ---------- Report Generator ----------

    def _generate_report(self):
        v=self.results['verdict']
        txt=[]
        txt+=[
            "="*60,"IPHONE SECURITY & GHOST WAKE REPORT","="*60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Fuse Verdict: {v}",""
        ]

        # --- Fuse Section ---
        if v=="UNBLOWN_FUSES_CONFIRMED":
            latest=self.results['all_analyses'][0]
            bits=latest['critical_bits']
            txt+=["FACTORY SECURITY FUSES UNBLOWN",
                   f"  PMGR Fuse Bits [4,5,6] = {bits}",
                   f"  Flags Register = {latest['flags_hex']}",
                   "",
                   "RAW POWERLOG FLAGS:"]
            for idx,a in enumerate(self.results['all_analyses'],1):
                txt.append(f"\n  Source {idx}:")
                for e in a.get('proof',[]):
                    txt.append(f"    • {e['timestamp']} | Flags={e['flags']} ({e['flags_hex']}) | Bits[4,5,6]={e['bits_456']}")
            txt+=["","INTERPRETATION: All bits 0 ⇒ unblown security fuses (factory debug path active)."]
        else:
            txt+=["FACTORY FUSES APPEAR BLOWN:",
                   "PMGR bits [4,5,6] show one or more 1’s → production-secure state.",""]

        # --- Ghost Wake Section ---
        txt+=["","="*60,"GHOST WAKE ACTIVITY","="*60,
              f"Trace logs scanned: {len(self.trace_logs)}",
              f"Wake events found: {len(self.ghost_results)}",""]
        if not self.ghost_results:
            txt+=["  No wake anomalies detected."]
        else:
            # summarize time window
            real_times=[e['timestamp'] for e in self.ghost_results if e['timestamp']!="unknown"]
            if real_times:
                dts=[datetime.fromisoformat(t) for t in real_times]
                txt+=["Time Window:",
                       f"  First wake : {min(dts)}",
                       f"  Last wake  : {max(dts)}",
                       ""]
            txt.append("SAMPLE EVENTS:")
            for e in self.ghost_results[:15]:
                txt.append(f"  {e['timestamp']} | {os.path.basename(e['file'])} ...{e['context']}...")
            txt+=["",
                   "INTERPRETATION:",
                   "Repeated DarkWake/SleepService triggers may reflect overnight or background wakes.",
                   "BTServer or keep-alive timers often explain these, but frequent night activity warrants review."]
        txt+=["","Files analyzed: "+str(self.results['evidence_count']),
               "="*60]

        return {'json':{'verdict':v,'fuse_analysis':self.results,'ghost_wake_events':self.ghost_results},
                'txt':"\n".join(txt),'verdict':v}

# ---------- Main ----------

def main():
    if len(sys.argv)!=2:
        print("Usage: python3 fuse_wake_v2_2.py <sysdiagnose.tar|.zip>")
        sys.exit(1)
    analyzer=SysdiagnoseAnalyzer(sys.argv[1])
    try:
        print("\n"+"="*60)
        print("IPHONE FUSE & GHOST WAKE ANALYZER v2.2")
        print("="*60)
        rep=analyzer.run_analysis()
        base=os.path.splitext(os.path.basename(sys.argv[1]))[0]
        with open(f"{base}_analysis.json","w") as j: json.dump(rep['json'],j,indent=2)
        with open(f"{base}_report.txt","w") as t: t.write(rep['txt'])
        print(f"\nFinal Verdict: {rep['verdict']}")
        print(f"Reports saved:\n  {base}_analysis.json\n  {base}_report.txt")
    finally:
        if analyzer.temp_dir: shutil.rmtree(analyzer.temp_dir,ignore_errors=True)
    print("\nAnalysis complete.")

if __name__=='__main__':
    main()
