---
name: CrackMapExec
type: tool
aliases: [CME]
platforms: [Windows]
references:
  - source_name: CME Github September 2018
    url: https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference
    description: "byt3bl33d3r. (2018, September 8). SMB: Command Reference."
  - source_name: Secureworks IRON LIBERTY July 2019
    url: https://www.secureworks.com/research/resurgent-iron-liberty-targeting-energy-sector
    description: "Secureworks. (2019, July 24). Resurgent Iron Liberty Targeting Energy Sector."
  - source_name: US-CERT TA18-074A
    url: https://www.us-cert.gov/ncas/alerts/TA18-074A
    description: "US-CERT. (2018, March 16). Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors."
  - source_name: TrendMicro POWERSTATS V3 June 2019
    url: https://blog.trendmicro.com/trendlabs-security-intelligence/muddywater-resurfaces-uses-multi-stage-backdoor-powerstats-v3-and-new-post-exploitation-tools/
    description: "Lunghi, D. and Horejsi, J. (2019, June 10). MuddyWater Resurfaces, Uses Multi-Stage Backdoor POWERSTATS V3 and New Post-Exploitation Tools."
  - source_name: Symantec MuddyWater Dec 2018
    url: https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group
    description: "Symantec DeepSight Adversary Intelligence Team. (2018, December 10). Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms."
  - source_name: CrowdStrike Carbon Spider August 2021
    url: https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/
    description: "Loui, E. and Reynolds, J. (2021, August 30). CARBON SPIDER Embraces Big Game Hunting, Part 1."
  - source_name: FireEye APT39 Jan 2019
    url: https://web.archive.org/web/2019/https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html
    description: "Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information."
  - source_name: BitDefender Chafer May 2020
    url: https://www.bitdefender.com/blog/labs/iranian-chafer-apt-targeted-air-transportation-and-government-in-kuwait-and-saudi-arabia/
    description: "Rusu, B. (2020, May 21). Iranian Chafer APT Targeted Air Transportation and Government in Kuwait and Saudi Arabia."
  - source_name: CISA GRU29155 2024
    url: https://www.cisa.gov/sites/default/files/2024-09/aa24-249a-russian-military-cyber-actors-target-us-and-global-critical-infrastructure.pdf
    description: "US Cybersecurity & Infrastructure Security Agency et al. (2024, September 5). Russian Military Cyber Actors Target U.S. and Global Critical Infrastructure."
---

Open-source post-exploitation framework written in Python for assessing Windows Active
Directory networks. It was built for penetration testers, and criminal and state-aligned
operators have also adopted it because it needs no implant on the targets and its traffic
looks like ordinary administration.

Given a username and password, a captured password hash or a Kerberos ticket, it takes a
list of addresses or a whole subnet and works through them in parallel over the Windows
file-sharing and remote-management protocols. It enumerates hosts, logged-on users,
network shares, domain accounts and groups, password policy and local drives, and lists
or reads files on the shares it can reach. It can try one password, or a list of
passwords, against many accounts and report which ones are valid.

Once it has administrative access it runs commands on the remote hosts, through the
remote service and scheduled-task mechanisms and the Windows management interfaces, and
can run scripts in the Windows scripting shell and change registry settings there. It dumps credential material:
password hashes from the local account database and the cached secrets of the security
subsystem, and from a domain controller the whole directory database. The recovered
hashes can then be used directly to authenticate to further hosts.

Defenders and government advisories have reported the tool in the hands of several
distinct operators, usually as a way to move laterally and collect credentials after
initial access. The group reports listed here describe which operators used it; the
tool's own documentation describes what each command does.
