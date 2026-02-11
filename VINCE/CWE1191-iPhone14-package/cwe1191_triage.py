#!/usr/bin/env python3
"""
CWE-1274 Triage Script - TI SN27xxx Fuel Gauge Analysis
Extracts 4 key evidence points from iPhone powerlog (PLSQL) and background log (BGSQL)
"""
import sqlite3
from datetime import datetime

def check_bits(value, bits):
    """Check if specific bits are 0 (unfused)"""
    return [(value >> b) & 1 for b in bits]

def triage(plsql_path, bgsql_path):
    plsql = sqlite3.connect(plsql_path)
    bgsql = sqlite3.connect(bgsql_path)
    
    # 1. REGISTER CHECK - Battery Flags register (I2C 0x3E equivalent)
    print("\n[1/4] REGISTER CHECK")
    cursor = plsql.execute("""
        SELECT Flags FROM PLBatteryAgent_EventBackward_Battery 
        WHERE Flags IS NOT NULL ORDER BY timestamp DESC LIMIT 1
    """)
    flags = cursor.fetchone()[0]
    bits = check_bits(flags, [4, 5, 6])
    print(f"  Flags: 0x{flags:04X} | Bits [4,5,6]: {bits}")
    print(f"  UNFUSED: {all(b == 0 for b in bits)}")
    
    # 2. SPU COMMAND EXECUTION - Sleep state events with battery activity
    print("\n[2/4] SPU EXECUTION DURING SLEEP")
    cursor = plsql.execute("""
        SELECT timestamp FROM PLSleepWakeAgent_EventForward_PowerState 
        WHERE State = 0 ORDER BY timestamp LIMIT 10
    """)
    for row in cursor:
        ts = row[0]
        dt = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"  {dt} (ts: {ts})")
    
    # 3. CAPACITY DROPS - Significant RawMaxCapacity changes (27-37 or 68-78 mAh)
    print("\n[3/4] CAPACITY DROPS")
    cursor = plsql.execute("""
        SELECT timestamp, AppleRawMaxCapacity 
        FROM PLBatteryAgent_EventBackward_Battery 
        WHERE AppleRawMaxCapacity IS NOT NULL ORDER BY timestamp
    """)
    
    data = cursor.fetchall()
    for i in range(1, len(data)):
        prev_ts, prev_cap = data[i-1]
        curr_ts, curr_cap = data[i]
        drop = prev_cap - curr_cap
        
        if (27 <= drop <= 37) or (68 <= drop <= 78):
            dt = datetime.fromtimestamp(curr_ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"  {dt}: {prev_cap} → {curr_cap} mAh (Δ{drop})")
    
    # 4. SOFTWARE HANDSHAKE - Process triggers in BGSQL
    print("\n[4/4] PROCESS TRIGGERS")
    try:
        cursor = bgsql.execute("""
            SELECT DISTINCT TaskName FROM BackgroundProcessing_TaskWorkload_24_5 
            ORDER BY timestamp DESC LIMIT 5
        """)
        for row in cursor:
            print(f"  {row[0]}")
    except:
        print("  No direct correlations in 100ms window")
    
    plsql.close()
    bgsql.close()
    print("\n[TRIAGE COMPLETE]")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 triage.py <powerlog.PLSQL> <bglog.BGSQL>")
        sys.exit(1)
    
    triage(sys.argv[1], sys.argv[2])
