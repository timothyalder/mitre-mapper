# CrackMapExec

- run_id: `20261003T162134Z-crackmapexec-eba47f`
- terminal state: **minted**
- domains / attempts: enterprise-attack (1)
- model: mcp-client; judge: none
- git: `6c4269f3e250-dirty`; prompt: `3bbb467e80b7`
- model calls: 0; tokens in/out: 0/0; wall: 77.349s
- ERROR rules: none
- WARN rules: none
- judge failed items: none
- zero-hit searches: 0
- fetch failures: 1
  - TrendMicro POWERSTATS V3 June 2019: not in frozen evidence
- unmatched actors: 0

## Mapping
### enterprise-attack
- T1018 Remote System Discovery -- CME Github September 2018
- T1135 Network Share Discovery -- CME Github September 2018
- T1033 System Owner/User Discovery -- CME Github September 2018
- T1087.002 Domain Account -- CME Github September 2018
- T1069.002 Domain Groups -- CME Github September 2018
- T1069.001 Local Groups -- CME Github September 2018
- T1201 Password Policy Discovery -- CME Github September 2018
- T1083 File and Directory Discovery -- CME Github September 2018
- T1110.003 Password Spraying -- CME Github September 2018
- T1550.002 Pass the Hash -- CME Github September 2018
- T1003.002 Security Account Manager -- CME Github September 2018
- T1003.004 LSA Secrets -- CME Github September 2018
- T1003.003 NTDS -- CME Github September 2018
- T1047 Windows Management Instrumentation -- CME Github September 2018
- T1053.005 Scheduled Task -- CME Github September 2018
- T1569.002 Service Execution -- CME Github September 2018
- T1059.001 PowerShell -- CME Github September 2018
- group G0069 MuddyWater (existing)

## Attempts
- enterprise-attack #1: lint clean
