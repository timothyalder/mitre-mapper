# Pegasus for iOS

- run_id: `20261003T130703Z-pegasus-for-ios-74ff83`
- terminal state: **minted**
- domains / attempts: mobile-attack (3)
- model: mcp-client; judge: none
- git: `6c4269f3e250-dirty`; prompt: `3bbb467e80b7`
- model calls: 0; tokens in/out: 0/0; wall: 74.955s
- ERROR rules: E012
- WARN rules: none
- judge failed items: none
- zero-hit searches: 0
- fetch failures: 1
  - Pegasus for iOS: not in frozen evidence
- unmatched actors: 0

## Mapping
### mobile-attack
- T1660 Phishing -- Lookout-Pegasus
- T1456 Drive-By Compromise -- PegasusCitizenLab
- T1404 Exploitation for Privilege Escalation -- Lookout-Pegasus
- T1398 Boot or Logon Initialization Scripts -- PegasusCitizenLab
- T1544 Ingress Tool Transfer -- Lookout-Pegasus
- T1631 Process Injection -- Lookout-Pegasus
- T1429 Audio Capture -- PegasusCitizenLab
- T1512 Video Capture -- PegasusCitizenLab
- T1430 Location Tracking -- Lookout-Pegasus
- T1636.004 SMS Messages -- Lookout-Pegasus
- T1636.003 Contact List -- Lookout-Pegasus
- T1636.001 Calendar Entries -- Lookout-Pegasus
- T1634.001 Keychain -- PegasusCitizenLab
- T1422.002 Wi-Fi Discovery -- Lookout-Pegasus
- T1409 Stored Application Data -- Lookout-Pegasus
- T1644 Out of Band Data -- PegasusCitizenLab
- T1646 Exfiltration Over C2 Channel -- PegasusCitizenLab
- T1630 Indicator Removal on Host -- Lookout-Pegasus

## Attempts
- mobile-attack #1: lint ERROR E012
- mobile-attack #2: lint ERROR E012
- mobile-attack #3: lint clean
