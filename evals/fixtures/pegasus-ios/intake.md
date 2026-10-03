---
name: Pegasus for iOS
type: malware
aliases: []
platforms: [iOS]
references:
  - source_name: PegasusCitizenLab
    url: https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/
    description: "Marczak, B. and Scott-Railton, J. (2016, August 24). The Million Dollar Dissident: NSO Group's iPhone Zero-Days used against a UAE Human Rights Defender."
  - source_name: Lookout-Pegasus
    url: https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-technical-analysis.pdf
    description: "Lookout. (2016). Technical Analysis of Pegasus Spyware."
  - source_name: Pegasus for iOS
    url: null
    description: "Intake note with no retrievable URL (exercises the null-URL fetch path)."
---

Commercial mobile surveillance implant for Apple iOS, sold to government customers by a
private vendor and deployed against journalists, lawyers and human rights defenders.

Delivery is by a link sent over SMS or messaging app. Opening the link triggers a chain of
previously unknown browser and kernel vulnerabilities that jailbreaks the handset silently,
with no further interaction from the target. Once resident, the implant installs itself
persistently and takes steps to stay hidden, including disabling the device's automatic
software updates so the vulnerabilities it relies on are not patched underneath it.

Operators use it to read and exfiltrate data held by other applications on the phone and to
turn the handset itself into a listening device. Reporting describes collection of messages
and call records, contents of chat and email clients, stored credentials, location, and
recording from the microphone and camera. Communications with the operator are encrypted
and the implant contains logic to remove itself if it believes it has been detected.

Attribution to a specific named intrusion set has not been established in the source
reporting.
