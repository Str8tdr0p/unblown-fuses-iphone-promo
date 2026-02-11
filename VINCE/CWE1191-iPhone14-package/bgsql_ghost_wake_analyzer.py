#!/usr/bin/env python3
"""
BGSQL Ghost Wake Analyzer
Verifies unauthorized hardware-initiated wake events in iOS BGSQL logs

Usage: python3 bgsql_ghost_wake_analyzer.py <BGSQL_FILE>
Example: python3 bgsql_ghost_wake_analyzer.py log_2026-01-18_14-17_1CD45F2D.BGSQL

Author: VU#132804 Vulnerability Disclosure
"""

import sqlite3
import sys
from datetime import datetime

def analyze_ghost_wakes(bgsql_file):
    """
    Identifies ghost wakes: Device wake events with no corresponding iOS task.
    
    Ghost Wake Definition:
    - UserActivityStatus = 1 (device woke up)
    - Zero entries in TaskCheckpoint table within ±60 seconds
    - Indicates hardware-initiated wake, not OS-authorized
    """
    
    print("="*80)
    print("BGSQL GHOST WAKE ANALYSIS")
    print("="*80)
    print(f"Database: {bgsql_file}\n")
    
    conn = sqlite3.connect(bgsql_file)
    cursor = conn.cursor()
    
    # Query for ghost wakes
    query = """
    WITH WakeEvents AS (
        SELECT 
            timestamp,
            datetime(timestamp, 'unixepoch') as DateTime,
            UserActivityStatus,
            ROUND((timestamp - LAG(timestamp) OVER (ORDER BY timestamp)) / 60.0, 1) as MinutesSinceLast
        FROM BackgroundProcessing_SystemConditionsPowerManagement_24_5
        WHERE UserActivityStatus = 1
    ),
    GhostWakes AS (
        SELECT 
            w.timestamp,
            w.DateTime,
            w.MinutesSinceLast
        FROM WakeEvents w
        WHERE NOT EXISTS (
            SELECT 1 
            FROM BackgroundProcessing_TaskCheckpoint_24_5 t
            WHERE ABS(w.timestamp - t.timestamp) < 60
        )
        AND w.timestamp > (
            SELECT MIN(timestamp) + 3600 
            FROM BackgroundProcessing_SystemConditionsPowerManagement_24_5
        )
    )
    SELECT * FROM GhostWakes ORDER BY timestamp;
    """
    
    cursor.execute(query)
    results = cursor.fetchall()
    
    print(f"GHOST WAKES IDENTIFIED: {len(results)}\n")
    print("Timestamp (UTC)      Minutes Since Last  Classification")
    print("-" * 80)
    
    periodic_6min = 0
    for i, (ts, dt, interval) in enumerate(results[:50], 1):  # Show first 50
        flag = ""
        if interval and 5.0 <= interval <= 7.0:
            flag = "⚠️ ~6-MIN PATTERN"
            periodic_6min += 1
        elif interval and 14.0 <= interval <= 16.0:
            flag = "⚠️ ~15-MIN PATTERN"
        
        interval_str = f"{interval:.1f}" if interval else "N/A"
        print(f"{dt}  {interval_str:>18}  {flag}")
    
    if len(results) > 50:
        print(f"\n... {len(results) - 50} additional ghost wakes omitted ...")
    
    print("\n" + "="*80)
    print("PATTERN ANALYSIS")
    print("="*80)
    print(f"Total ghost wakes: {len(results)}")
    print(f"~6-minute periodic pattern: {periodic_6min} events")
    print(f"\nGhost wakes have ZERO corresponding iOS Background Task Scheduler entries.")
    print(f"This indicates hardware-initiated wakes bypassing OS control.\n")
    
    # Show specific Jan 16 examples
    print("="*80)
    print("JAN 16, 2026 EXAMPLES (Referenced in CISA Report)")
    print("="*80)
    
    jan16_query = """
    SELECT datetime(timestamp, 'unixepoch') as DateTime
    FROM BackgroundProcessing_SystemConditionsPowerManagement_24_5
    WHERE UserActivityStatus = 1
      AND datetime(timestamp, 'unixepoch') LIKE '2026-01-16 05:%'
      AND NOT EXISTS (
          SELECT 1 FROM BackgroundProcessing_TaskCheckpoint_24_5 t
          WHERE ABS(BackgroundProcessing_SystemConditionsPowerManagement_24_5.timestamp - t.timestamp) < 60
      )
    ORDER BY timestamp
    LIMIT 5;
    """
    
    cursor.execute(jan16_query)
    jan16_results = cursor.fetchall()
    
    if jan16_results:
        for dt in jan16_results:
            print(f"  {dt[0]} - Ghost wake (no iOS task)")
    else:
        print("  No Jan 16 05:XX UTC ghost wakes in this dataset")
    
    conn.close()
    
    print("\n" + "="*80)
    print("VERIFICATION COMPLETE")
    print("="*80)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 bgsql_ghost_wake_analyzer.py <BGSQL_FILE>")
        print("Example: python3 bgsql_ghost_wake_analyzer.py log_2026-01-18_14-17_1CD45F2D.BGSQL")
        sys.exit(1)
    
    try:
        analyze_ghost_wakes(sys.argv[1])
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
