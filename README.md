# CVE-2026-25251

## TI SN27xxx shipped production iPhones found with UNBLOWN DEBUG FUSES 
**A16 (14 Pro Max) + A17 Pro (15 Pro Max) = Supply Chain Concern**

 **RISK:** Persistent JTAG/I2C hardware debug access survives all iOS updates, factory resets, Secure Enclave protections. Attackers mount 384KB hidden AON partitions for permanent foothold. VULNERABLE SINCE ~2022-2024. (iPhone 14 & 15 Pro Max confirmed; likely broader Apple ecosystem)

 ---
 
**MITRE refusal to publish CVE leaves users blind... observed exploitation March 2025-Jan 2026, but hardware flaw exists since devices left factories years ago. Users left unknown and continue to remain defenseless.**

---

![CISA VINCE](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/VINCE/vu132084-description.png)

## The Stall (MITRE Email Chain)
1. [Receipt](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/MITRE%20Emails/1.receipt.pdf) **CVE Request**
2. [CVE Reserved](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/MITRE%20Emails/2.receipt.pdf) **CVE-2026-25251 Reserved**
3. [Publication Request](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/MITRE%20Emails/3.receipt.pdf) 
4. [Reference Provided](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/MITRE%20Emails/4.receipt.pdf)  **MITRE'S Missing Requiremet for Publication Provided**
5. [[Dispute] Halt](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/blob/main/MITRE%20Emails/4.receipt.pdf) **Refusal To Publish Without Reasoning**

## A16 PROOF (iPhone 14 Pro Max)  
**[VINCE Package](/VINCE/CWE1191-iPhone14-package/)** → Register **0x2081 Bits 4-6=0 UNFUSED**

```bash
cd VINCE/cwe1191-iPhone14-package/
python3 cwe1191_triage.py powerlog_*.PLSQL log_*.BGSQL      # → FUSES
python3 bgsql_ghost_wake_analyzer.py log_*.BGSQL           # → 756 GHOST WAKES
```

### LIVE EXPLOITATION (Feb 8, 2026 - iOS 26.2.1)

**CISA KEV submitted 2026-02-11 (vulnerability@mail.cisa.dhs.gov) | BOD 22-01**

iPhone 14 Pro Max (D74AP, build 23C71) LiveData.tracev3 capture during active exploitation:
- 8x CoreSight register 0x2081 hits (OTP bits 4-6 = 0, fuses UNBLOWN)
- Kernel debug events type 0xefd6 + KTRR/PAC bypass 0x3535
- gateway.icloud.com:443 CloudKit C2 during debug sessions (11 connections)
- SHA256: c335e48e733f7e80b3e4c3779f45a72439917492ac6293d87a4e044cf599216b

[**Full Exploitation Package**](https://github.com/Str8tdr0p/unblown-fuses-iphone-promo/tree/main/LIVE-EXPLOITATION)


### Repository Structure 

```
unblown-fuses-iphone-promo/
├── README.md                      # This File
├── MITRE-Emails/                  # 10 files total (5 emails × PDF screenshot + EML raw)
│   ├── 1. cve request             # "We've received your CVE request"
│   ├── 2. cve-reserved            # "CVE-2026-25251 issued"        
│   ├── 3. publication request
│   ├── 4. response                # Missing URL Provided
│   └── 5. Refusal to publish      # Publication paused
├── VINCE/                         # README.md
│   ├── vu132084-description.png   # CISA portal screenshot (OTP fuses, JTAG, 384KB AON)
│   └── cwe1191-package/           # iPhone 14 Pro Max A16 confirmation (5 files)
│       ├── README.md              # Package verification guide
│       ├── CWE-1191_EVIDENCE_REPORT.txt
│       ├── powerlog_*.PLSQL
│       ├── log_*.BGSQL
│       ├── cwe1191_triage.py      # → Register 0x2081 UNFUSED
│       └── bgsql_ghost_wake_analyzer.py  # → 756 ghost wakes
├── LIVE-EXPLOITATION/             
│   ├── README.md                         # Verification guide
│   ├── Report1_Hardware_Debug_CVE-2026-25251.txt
│   ├── Report2_CloudKit_Exfil_CVE-2026-25252.txt
│   ├── logdata_LiveData.tracev3          # Raw 3.1MB binary log (SHA256 verified)
│   ├── tracev3_exploitation_analyzer.py  # → Report 1 (0x2081 detection)
│   └── tracev3_network_analyzer.py       # → Report 2 (CloudKit C2)
