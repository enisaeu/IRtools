Measures for proactive detection of incidents
=============================================

## NIDS

NIDS systems are used to monitor network traffic in order to search for
evidences of malicious operations in observed network. A basic
deployment of a NIDS system consists of a probe which monitors network
traffic and system for collection of logs/alerts. Depending on size of
network and bandwidth, the system can depend on a single probe (small
networks) or be more complex, with multiple probes and multiple
collection systems. NIDS systems are fed with rules describing
suspicious behavior, for which an alert should be issued. The rules can be written
by analysts, but they are also available as sets, either open sourced
(free) or commercial (paid). The messages alerted by a NIDS system have
to be monitored by an analyst, who can decide about the significance and
priority of information provided by the system. To help in the analyst’s
work, logs from a NIDS system can be forwarded to aggregation,
correlation and visualization systems, including SIEM (Security
Information and Event Management) systems. Usage scenarios of NIDS
systems by CSIRTs depend on the team's constituency. NIDS systems can be
used for monitoring internal networks, but also for monitoring
research/laboratory networks, for example networks of sandbox systems.

### Evaluation

**Type:** Alerts.

**Timeliness:** Excellent; near realtime.

**Accuracy:** Poor; quality of alerts depends on the rules used; typically verification is needed due to common false positives.

**Ease of use:** Excellent; alerts are usually easy to interpret and tools provide a convenient way to browse the results.

**Coverage:** Monitoring of local infrastructure; coverage of threats depends on the rules used.

**Resources:** Fair; analysts need to verify alerts, which can be large in number.

**Scalability:** Good; scales with the number of sensors.

**Extensibility:** Excellent; all mainstream tools support rule-based configuration; typically tools provide plugin mechanisms.

**Completeness:** Fair; there is limited information about the type of threat detected and basic network information.



### Examples of tools

#### Snort
![GitHub stars](https://img.shields.io/github/stars/snort3/snort3?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/snort3/snort3?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/snort3/snort3?style=flat-square&cacheSeconds=86400)

Website: https://www.snort.org/

Maintainer: Cisco

License: GPL 2.0

#### Suricata
![GitHub stars](https://img.shields.io/github/stars/OISF/suricata?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/OISF/suricata?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/OISF/suricata?style=flat-square&cacheSeconds=86400)

Website: https://suricata-ids.org

Maintainer: The Open Information Security Foundation

License: GPL 2.0

#### Bro/Zeek
![GitHub stars](https://img.shields.io/github/stars/zeek/zeek?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/zeek/zeek?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/zeek/zeek?style=flat-square&cacheSeconds=86400)

Website: https://www.zeek.org/

Maintainer: Zeek project

License: BSD

#### RITA
![GitHub stars](https://img.shields.io/github/stars/activecm/rita?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/activecm/rita?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/activecm/rita?style=flat-square&cacheSeconds=86400)

Website: https://github.com/activecm/rita

Maintainer: Active Countermeasures

License: GPL 3.0

#### AIEngine

_no GitHub repository_

Website: https://bitbucket.org/camp0/aiengine/

Maintainer: individual

License: GPL 2.0



## Network flow monitoring

Network flow monitoring systems provide means for extraction of network flow information from network traffic. Some of the systems also help in basic analysis of network flows, including bandwidth level, protocol usage and IP addresses involved in communication. Network flows can be also used as input in specialised network anomaly detection tools.

### Evaluation

**Type:** Alerts, support.

**Timeliness:** Excellent; alerts on blacklist hits are near realtime; some detection methods may work over longer time periods, for example anomaly detection.

**Accuracy:** Poor; alerts require verification.

**Ease of use:** Good; mature specialized GUI and CLI tools with query capabilities, dashboards.

**Coverage:** Monitoring of local infrastructure, either just external connections or inter-network traffic as well; the biggest issue is that no payloads are saved.

**Resources:** Fair; analysts may have a lot of alerts to investigate; additionally the flow monitoring solutions are often custom-built from ready-made components such as flow collectors, message brokers and databases with appropriate orchestration, which requires some extra resources to maintain.

**Scalability:** Good; scales with the number of sensors; for large networks the cost of the backend may be significant.

**Extensibility:** N/A; varies, tool-dependent.

**Completeness:** Poor; missing payloads means that further correlation is necessary; anomaly detection may provide limited context.


### Examples of tools

#### NFSen
![GitHub last commit](https://img.shields.io/github/last-commit/p-alik/nfsen?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/p-alik/nfsen?style=flat-square&cacheSeconds=86400)

Website: http://nfsen.sourceforge.net/

Maintainer: individual

License: BSD

#### pmacctd
![GitHub stars](https://img.shields.io/github/stars/paololucente/pmacct-contrib?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/paololucente/pmacct-contrib?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/paololucente/pmacct-contrib?style=flat-square&cacheSeconds=86400)

Website: http://www.pmacct.net/

Maintainer: individual

License: GPL 2.0

#### vflow
![GitHub stars](https://img.shields.io/github/stars/VerizonDigital/vflow?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/VerizonDigital/vflow?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/VerizonDigital/vflow?style=flat-square&cacheSeconds=86400)

Website: https://github.com/VerizonDigital/vflow

Maintainer: Verizon Digital Media Services

License: Apache 2.0

#### Ntopng
![GitHub stars](https://img.shields.io/github/stars/ntop/ntopng?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/ntop/ntopng?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ntop/ntopng?style=flat-square&cacheSeconds=86400)

Website: https://www.ntop.org/products/traffic-analysis/ntop/

Maintainer: ntop

License: GPL 3.0

#### nfdump
![GitHub stars](https://img.shields.io/github/stars/phaag/nfdump?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/phaag/nfdump?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/phaag/nfdump?style=flat-square&cacheSeconds=86400)

Website: https://github.com/phaag/nfdump

Maintainer: individual

License: BSD

#### SiLK

_no GitHub repository_

Website: https://tools.netsa.cert.org/silk/

Maintainer: CERT NetSA

License: GPL 2.0

#### GoFlow
![GitHub stars](https://img.shields.io/github/stars/cloudflare/goflow?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/cloudflare/goflow?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/cloudflare/goflow?style=flat-square&cacheSeconds=86400)

Website: https://github.com/cloudflare/goflow

Maintainer: Cloudflare

License: BSD 3-Clause "New" or "Revised" License

#### Yaf

_no GitHub repository_

Website: https://tools.netsa.cert.org/yaf/

Maintainer: CERT NetSA

License: Unknown

#### Argus

_no GitHub repository_

Website: https://openargus.org/

Maintainer: QoSient

License: GPL

#### Joy
![GitHub stars](https://img.shields.io/github/stars/cisco/joy?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/cisco/joy?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/cisco/joy?style=flat-square&cacheSeconds=86400)

Website: https://github.com/cisco/joy

Maintainer: Cisco

License: BSD

#### ipt\_NETFLOW
![GitHub stars](https://img.shields.io/github/stars/aabc/ipt-netflow?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/aabc/ipt-netflow?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/aabc/ipt-netflow?style=flat-square&cacheSeconds=86400)

Website: https://github.com/aabc/ipt-netflow

Maintainer: individual

License: GPL 2.0



## Full packet capture

Full packet capture systems are used to provide means for archiving
network traffic, what can be later used for precise analysis by analysts
or automatic systems. Such systems can simply save network traffic to
preferred file format, but some of them also provide tools for
exploration and basic analysis of the network traffic.

### Evaluation

**Type:** Support.

**Timeliness:** Excellent; data can be collected in realtime.

**Accuracy:** Good; actual contents of the network traffic; protocol analysis can fail sometimes; attackers can spoof origin of packets.

**Ease of use:** Good; requires some expertise.

**Coverage:** Monitoring of local infrastructure; the biggest problem is lack of payload for encrypted connections unless TLS inspection is deployed.

**Resources:** Good; systems do not require much maintenance after the initial setup.

**Scalability:** Fair; scales with the number of sensors; for medium and large networks the amount of data collected will be a challenge and the hardware costs of the backend will be significant, this can be alleviated by keeping data for shorter periods.

**Extensibility:** Good; details depend on the tool.

**Completeness:** Good; except for encrypted or obfuscated payloads.


### Examples of tools

#### Moloch
![GitHub stars](https://img.shields.io/github/stars/aol/moloch?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/aol/moloch?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/aol/moloch?style=flat-square&cacheSeconds=86400)

Website: https://molo.ch/

Maintainer: AOL

License: Apache 2.0

#### OpenFPC
![GitHub stars](https://img.shields.io/github/stars/leonward/OpenFPC?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/leonward/OpenFPC?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/leonward/OpenFPC?style=flat-square&cacheSeconds=86400)

Website: http://www.openfpc.org/

Maintainer: individual

License: GPL 2.0

#### Stenographer
![GitHub stars](https://img.shields.io/github/stars/google/stenographer?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/google/stenographer?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/google/stenographer?style=flat-square&cacheSeconds=86400)

Website: https://github.com/google/stenographer

Maintainer: Google

License: Apache 2.0

#### PcapDB
![GitHub stars](https://img.shields.io/github/stars/dirtbags/pcapdb?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/dirtbags/pcapdb?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/dirtbags/pcapdb?style=flat-square&cacheSeconds=86400)

Website: https://github.com/dirtbags/pcapdb

Maintainer: The Dirtbags

License: BSD 2-Clause



## Sinkholing

Sinkhole systems are be used to discover malware infections by
monitoring host connections. After ceasing C&C server address, sinkhole
server can be used as replacement to the original botnet’s
infrastructure, and track all connections made by bots. With that data,
analysts can provide information about the number of infections,
geographical distribution, most impacted networks, etc.


### Evaluation

**Type:** Alerts.

**Timeliness:** Excellent; realtime.

**Accuracy:** Excellent; assuming local deployment otherwise many internet scans will be registered which can significantly lower the accuracy.

**Ease of use:** Good; output is easy to work with.

**Coverage:** Local deployment: monitoring of own infrastructure for known threats; global deployment: monitoring of victims of specific botnet, RAT, etc.; global sinkholing is useful primary for notifying other entities.

**Resources:** Excellent.

**Scalability:** Excellent; typical solutions for load balancing can be employed; for global botnet sinkholing hardware investments may be required for storage.

**Extensibility:** N/A; typically custom solutions are deployed.

**Completeness:** Good; can be excellent if bots can be identified, for example using HTTP headers.


### Examples of tools



## Monitoring of internet routing

Monitoring of internet routing can provide information about status of
routing paths and thus be used to detect attacks, for example BGP
protocol hijacking.


### Evaluation

**Type:** Alerts.

**Timeliness:** Excellent; realtime.

**Accuracy:** Fair; alerts need verification.

**Ease of use:** Fair; Requires expertise to operate; COTS services are easy for general use.

**Coverage:** Visibility into global events; alerts are generated for the infrastructure of interest only.

**Resources:** Good.

**Scalability:** Fair; multiple sources of the BGP data can be used however there are diminishing results of adding new ones.

**Extensibility:** Fair; tool-dependent.

**Completeness:** Good; typically historical data is available.


### Examples of tools

#### BGPalerter
![GitHub stars](https://img.shields.io/github/stars/nttgin/BGPalerter?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/nttgin/BGPalerter?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nttgin/BGPalerter?style=flat-square&cacheSeconds=86400)

Website: https://github.com/nttgin/BGPalerter

Maintainer: NTT Global IP Network

License: BSD 3-Clause

#### bgp-watcher
![GitHub stars](https://img.shields.io/github/stars/woanware/bgp-watcher?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/woanware/bgp-watcher?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/woanware/bgp-watcher?style=flat-square&cacheSeconds=86400)

Website: https://github.com/woanware/bgp-watcher

Maintainer: individual

License: Unknown

#### BGPmon (tool)
![GitHub stars](https://img.shields.io/github/stars/CSUNetSec/bgpmon?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/CSUNetSec/bgpmon?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/CSUNetSec/bgpmon?style=flat-square&cacheSeconds=86400)

Website: https://www.bgpmon.io/

Maintainer: Colorado State University

License: BSD 2-Clause

#### BGPmon (service)

_closed source_

Website: https://www.bgpmon.net/

Vendor: Cisco

License: Proprietary



## Passive monitoring of unused IP space (network telescope/darknet)

Passive monitoring of unused IP space (also known as network telescope
or darknet) can help in identifying network attacks. As the monitored IP
addresses are unassigned, no network traffic should be directed on them.
From such perspective, any packets observed at these addresses are usually
sent by victims of reflected Denial of Service attacks or automatic
systems scanning the Internet, for example to find vulnerable hosts or
to exploit vulnerable services.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Good; realtime for some types of alerts; analyses can be run periodically, which may mean that the results are available only after some hours.

**Accuracy:** Poor; this method will susceptible to spoofing; relevant traffic is mixed with packets resulting from harmless misconfiguration or of unknown purpose.

**Ease of use:** Poor; except for predefined alerts generated by network telescopes, handling of the collected data is time-intensive and requires expertise.

**Coverage:** The traffic collected corresponds to various events world-wide; this measure is used primarily to understand global threats, not particular networks of interest.

**Resources:** Poor; no COTS solutions, analysis is time-intensive.

**Scalability:** Good; the quality of the information will improve with the increase of the monitored address space, however there will be diminishing results with each IP; depending on the size of the monitored address space and how much detail is stored, the backend for processing and storage may require non-negligible investment.

**Extensibility:** N/A; typically custom solutions are deployed.

**Completeness:** Fair; for some predefined events the level of detail is satisfactory; often further research is required to understand the nature of traffic.


### Examples of tools



## Systems for aggregation, correlation and visualization of logs and other event data

Systems for aggregation, correlation and visualization of logs and other
event data is an umbrella category grouping many systems. They gather
big amounts of data from logging/monitoring systems and process them in
order to help analysts monitor the infrastructure. Depending on type
of system, they aggregate data, correlate them and visualize to present
information that is most crucial to analysts. An example of system type, which
provide all of these tasks is Security Information and Event Management
(SIEM). SIEM can gather data from network monitoring systems like NIDS
or endpoint monitoring systems, providing analysts with means for monitoring
and inspection of defended infrastructure. Such measure is excellent for
the purpose of fusion of all security monitoring data in the organization.

### Evaluation

**Type:** Alerts, support.

**Timeliness:** Good; data can be ingested in realtime but in the end depend on the timeliness of the input; some analyses can be run periodically (for example daily queries).

**Accuracy:** Good; depends on proper configuration and prepared queries.

**Ease of use:** Fair; mature user interfaces and APIs with a lot of functionality; it may be difficult to master these tools, however typical tasks have a moderate learning curve.

**Coverage:** All information relevant to the monitored infrastructure; the actual coverage depends on inputs.

**Resources:** Poor; to achieve good results, substantial time is needed for configuration, integration of data sources, preparing queries and dashboards.

**Scalability:** Fair; Commercial solutions are expensive to scale; significant hardware investment may be required for storing large amount of logs; dedicated staff can be needed to keep the systems operational at a certain scale.

**Extensibility:** Excellent; multiple ways to interact with the systems through APIs and various plugin mechanisms.

**Completeness:** Excellent; assuming sufficient data inputs have been configured.


### Examples of tools

#### MozDef
![GitHub stars](https://img.shields.io/github/stars/mozilla/MozDef?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/mozilla/MozDef?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/mozilla/MozDef?style=flat-square&cacheSeconds=86400)

Website: https://github.com/mozilla/MozDef

Maintainer: Mozilla

License: MPL 2.0

#### OSSEC
![GitHub stars](https://img.shields.io/github/stars/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)

Website: https://www.ossec.net/

Maintainer: OSSEC Project

License: GPL 2.0

#### OSSIM
![GitHub stars](https://img.shields.io/github/stars/ossimlabs/ossim?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/ossimlabs/ossim?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ossimlabs/ossim?style=flat-square&cacheSeconds=86400)

Website: https://www.alienvault.com/products/ossim

Maintainer: Alienvault

License: Unknown

#### maltrail
![GitHub stars](https://img.shields.io/github/stars/stamparm/maltrail?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/stamparm/maltrail?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/stamparm/maltrail?style=flat-square&cacheSeconds=86400)

Website: https://github.com/stamparm/maltrail

Maintainer: individual

License: MIT

#### Malcolm
![GitHub stars](https://img.shields.io/github/stars/idaholab/Malcolm?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/idaholab/Malcolm?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/idaholab/Malcolm?style=flat-square&cacheSeconds=86400)

Website: https://github.com/idaholab/Malcolm

Maintainer: Idaho National Laboratory

License: Unknown

#### Hunting ELK
![GitHub stars](https://img.shields.io/github/stars/Cyb3rWard0g/HELK?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Cyb3rWard0g/HELK?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Cyb3rWard0g/HELK?style=flat-square&cacheSeconds=86400)

Website: https://github.com/Cyb3rWard0g/HELK

Maintainer: individual

License: GPL 3.0

#### ELK
![GitHub stars](https://img.shields.io/github/stars/elastic/elasticsearch?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/elastic/elasticsearch?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/elastic/elasticsearch?style=flat-square&cacheSeconds=86400)

Website: https://www.elastic.co

Maintainer: Elasticsearch B.V.

License: Elastic License or Apache License 2.0

#### Sigma Converter
![GitHub stars](https://img.shields.io/github/stars/Neo23x0/sigma?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Neo23x0/sigma?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Neo23x0/sigma?style=flat-square&cacheSeconds=86400)

Website: https://github.com/Neo23x0/sigma

Maintainer: individuals

License: LGPL 3.0



## Monitoring specific to industrial control systems

Monitoring systems specific to industrial control systems (ICS/SCADA) is often similar to regular network monitoring, however industrial communication protocols are much different from a IT networks. The fact that ICS often have certification requirements and are isolated from IT networks poses some challenges with developing good monitoring capabilities. This is one of the reasons that ICS monitoring is dominated by commercial vendors and open source solutions are much less used. The evaluation below covers mainstream commercial offerings only; examples refer to selected open source tools but they have a different scope in functionality.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Excellent; realtime.

**Accuracy:** Good; detection is often based on anomaly detection: this approach applied to ICS yield better results compared to IT networks, since OT (Operational Technology) environments typically do not undergo unplanned changes.

**Ease of use:** Excellent; monitoring tools are designed to be accessible by ICS engineers.

**Coverage:** Monitoring of local infrastructure; network traffic is typically obtained through taps; the biggest issue is presence of uncommon or custom protocols that are not supported by the monitoring tools, which means that it is not possible to inspect commands and values.

**Resources:** Poor; deployment of ICS monitoring is often time consuming and costly; a lot of complexity is caused by certification requirements; once installed ongoing effort for analysts should not be significant, as there is not a large number of alerts to investigate.

**Scalability:** Good.

**Extensibility:** Fair; tools support rule-based configuration; any major customisations are typically not possible without involving a vendor.

**Completeness:** Good; for supported protocols, full visibility into control commands and process values.


### Examples of tools

#### GRASSMARLIN
![GitHub stars](https://img.shields.io/github/stars/nsacyber/GRASSMARLIN?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/nsacyber/GRASSMARLIN?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nsacyber/GRASSMARLIN?style=flat-square&cacheSeconds=86400)

Website: https://github.com/nsacyber/GRASSMARLIN

Maintainer: NSA Cyber

License: LGPL 3.0

#### Splonebox
![GitHub stars](https://img.shields.io/github/stars/splone/splonebox-core?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/splone/splonebox-core?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/splone/splonebox-core?style=flat-square&cacheSeconds=86400)

Website: https://splone.com/splonebox/

Maintainer: splone UG

License: AGPL 3.0



## Monitoring of cloud services

Adoption of cloud services is increasing both for enterprise and governmental institutions. Nowadays, major providers offer much more rich and complex set of services than just hosting virtual machines and having a complete understanding of the protected assets in such environment might be difficult. However, the primary concern for defense is that the infrastructure cannot be monitored directly, which makes detection of suspicious activities a challenge. Major cloud providers offer in-house specialised security tools that allow to collect and analyse logs and monitor network traffic. Capabilities of such tools vary significantly between providers: in few cases their features address teams' need for monitoring and detection. Majority of providers, especially medium and small ones, do not have sufficient offering in this regard. The evaluation below is based on commercial in-house solutions from two cloud providers and focus on monitoring of virtual machines and not other cloud services. Smaller providers and standalone open source tools have not been taken into consideration, as their capabilities is too far limited and making a generalisation impossible.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Good; several minutes of delay.

**Accuracy:** Good; for vendor-provided images and standard software there should be a small number of false positives.

**Ease of use:** Good; regular web-based interfaces for analysts are easy to use; command-line or other advanced tools might have a steep learning curve.

**Coverage:** Monitoring of network traffic and logs from VMs; endpoint monitoring typically depend on having a standard agent installed.

**Resources:** Poor; hosted security tools are expensive, even more if any customisations are needed; substantial time investment is needed for the initial configuration; changes to services run in the cloud impose additional maintenance burden.

**Scalability:** N/A

**Extensibility:** Good; flexible rule-based configuration; anomaly detection possible if activity baselines are predefined.

**Completeness:** ~=~ IDS


### Examples of tools

#### Scout Suite
![GitHub stars](https://img.shields.io/github/stars/nccgroup/ScoutSuite?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/nccgroup/ScoutSuite?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nccgroup/ScoutSuite?style=flat-square&cacheSeconds=86400)

Website: https://github.com/nccgroup/ScoutSuite

Maintainer: NCC Group Plc

License: GPL 2.0

#### Security Monkey
![GitHub stars](https://img.shields.io/github/stars/Netflix/security_monkey?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Netflix/security_monkey?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Netflix/security_monkey?style=flat-square&cacheSeconds=86400)

Website: https://github.com/Netflix/security_monkey

Maintainer: Netflix

License: Apache 2.0



## Passive DNS

Passive DNS (PDNS) systems gather information about DNS records in particular
time points, in order to provide historical information about such
records. The systems help in tracking changes of malicious
infrastructure in time, but also provide last known IP address of a
domain if the DNS record is no longer available.


### Evaluation

**Type:** Support.

**Timeliness:** Excellent; can be updated in realtime.

**Accuracy:** Excellent; PDNS is based on the actual queries and answers so it corresponds to actual resolutions of domains at certain points in time.

**Ease of use:** Excellent; data can be interpreted quickly and is supported by analytical tools.

**Coverage:** All domains resolved within the local infrastructure can be monitored (data from local resolvers); clients using external resolvers, especially using DNS-over-HTTP (DoH) will avoid monitoring; global coverage (important for investigations) depends on the provider.

**Resources:** Excellent; low effort.

**Scalability:** Good; scales with the number of sensors; monitoring more DNS traffic increase coverage but has diminishing returns.

**Extensibility:** N/A; often custom solutions are used.

**Completeness:** Fair; typically PDNS is used for correlation with other information and not standalone.


### Examples of tools

#### PassiveDNS
![GitHub stars](https://img.shields.io/github/stars/gamelinux/passivedns?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/gamelinux/passivedns?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/gamelinux/passivedns?style=flat-square&cacheSeconds=86400)

Website: https://github.com/gamelinux/passivedns

Maintainer: individual

License: Unknown

#### Circl.lu - PDNS service

Website: https://www.circl.lu/services/passive-dns/

Maintainer: CIRCL

License: Unknown

#### DNSDB.info (service)

Website: https://www.dnsdb.info/

Maintainer: Farsight

License: Unknown

#### Passivetotal (service)

Website: https://community.riskiq.com/

Maintainer: RiskIQ

License: Unknown

#### Cisco Umbrella Investigate (service)

Website: https://umbrella.cisco.com/products/threat-intelligence

Maintainer: Cisco

License: Proprietary

#### analyzer-d4-passivedns
![GitHub stars](https://img.shields.io/github/stars/D4-project/analyzer-d4-passivedns?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/D4-project/analyzer-d4-passivedns?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/D4-project/analyzer-d4-passivedns?style=flat-square&cacheSeconds=86400)

Website: https://github.com/D4-project/analyzer-d4-passivedns

Maintainer: CIRCL

License: AGPL 3.0



## DNS request monitoring

DNS request monitoring systems provide information about how often and
when certain domain names were queried and by which addresses. Thanks to
that, extended analyses can be performed, including popularity of
domains, their activity lifetime, but also tracking of botnet clients
when monitoring known C&C domains.


### Evaluation

**Type:** Support.

**Timeliness:** Excellent; realtime.

**Accuracy:** Good; data is coming from actual DNS queries however, without answers from authoritative name servers, data can contain some noise.

**Ease of use:** Good; data are easy to interpret.

**Coverage:** All domains queried from the local infrastructure can be monitored (data from local resolvers); clients using external resolvers, especially using DNS-over-HTTP (DoH) will avoid monitoring; global coverage (important for investigations) depends on the provider but there are much fewer providers than for PDNS.

**Resources:** Excellent; low effort.

**Scalability:** Good; scales with the number of sensors; monitoring more DNS traffic increases coverage but has diminishing returns.

**Extensibility:** N/A; often custom solutions are used.

**Completeness:** Good; may reveal the profile (network or geographic distribution) of clients requesting a domain.


### Examples of tools

#### Cisco Umbrella Investigate (service)

Website: https://umbrella.cisco.com/products/threat-intelligence

Maintainer: Cisco

License: Proprietary



## Other DNS monitoring

DNS monitoring other than passive DNS and DNS request monitoring
includes, for example, monitoring of new domain names in search of
phishing sites or presence of domain names generated with DGA
algorithms.


### Evaluation

**Type:** Alert, support.

**Timeliness:** Poor; depends on the data source but can have a delay up to 24 hours.

**Accuracy:** Poor; typically all suspicious domains need to manually verified.

**Ease of use:** Fair; depends on the tooling.

**Coverage:** In-house tools usually cover only a few selected top-level domains (TLDs).

**Resources:** Fair; analysts need to verify identified domains; often a custom solution which requires maintenance.

**Scalability:** N/A

**Extensibility:** N/A; often custom solutions are used.

**Completeness:** Poor; needs further enrichment and correlation; post-GDPR important details in WHOIS are not easily accessible anymore.


### Examples of tools

#### Centralized Zone Data Service (service)

Website: https://czds.icann.org/

Maintainer: ICANN

License: Unknown



## Endpoint monitoring

Endpoint monitoring systems provide means for gathering and logging
information about events occurring on endpoint environments. Events can
include application logs, file system monitoring or configuration
monitoring. The gathered data can be then forwarded to aggregation
systems such as SIEMs.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Excellent; realtime.

**Accuracy:** Fair; actual accuracy varies, depends on the quality of rules and signatures used for identifying suspicious behaviour.

**Ease of use:** Fair; requires expertise to interpret and search the logs.

**Coverage:** Monitoring of local infrastructure; coverage depends on how widely the collection has been implemented.

**Resources:** Fair; can generate large amount of logs that need storage and indexing, this implies investments in the backend hardware.

**Scalability:** Fair; scaling can pose an IT challenge, since agents need to be deployed on a wide range and large number of endpoint devices.

**Extensibility:** N/A; tool-dependent.

**Completeness:** Good; endpoint logs can provide details that are not possible to obtain otherwise (for example from network traffic).


### Examples of tools

#### osquery
![GitHub stars](https://img.shields.io/github/stars/osquery/osquery?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/osquery/osquery?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/osquery/osquery?style=flat-square&cacheSeconds=86400)

Website: https://github.com/osquery/osquery

Maintainer: osquery project

License: Multiple licences

#### Sysmon

Website: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Maintainer: Microsoft

License: Proprietary

#### OSSEC
![GitHub stars](https://img.shields.io/github/stars/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/ossec/ossec-hids?style=flat-square&cacheSeconds=86400)

Website: https://github.com/ossec/ossec-hids

Maintainer: Atomicorp

License: Multiple licences

#### Wazuh
![GitHub stars](https://img.shields.io/github/stars/wazuh/wazuh?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/wazuh/wazuh?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/wazuh/wazuh?style=flat-square&cacheSeconds=86400)

Website: https://github.com/wazuh/wazuh

Maintainer: Wazuh Inc.

License: Multiple licences

#### Weakforced
![GitHub stars](https://img.shields.io/github/stars/PowerDNS/weakforced?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/PowerDNS/weakforced?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/PowerDNS/weakforced?style=flat-square&cacheSeconds=86400)

Website: https://github.com/PowerDNS/weakforced

Maintainer: PowerDNS

License: GPL 3.0

#### StreamAlert
![GitHub stars](https://img.shields.io/github/stars/airbnb/streamalert?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/airbnb/streamalert?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/airbnb/streamalert?style=flat-square&cacheSeconds=86400)

Website: https://github.com/airbnb/streamalert

Maintainer: Airbnb

License: Apache 2.0

#### Zentral
![GitHub stars](https://img.shields.io/github/stars/zentralopensource/zentral?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/zentralopensource/zentral?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/zentralopensource/zentral?style=flat-square&cacheSeconds=86400)

Website: https://github.com/zentralopensource/zentral

Maintainer: Zentral

License: Apache 2.0

1#### Velociraptor
![GitHub stars](https://img.shields.io/github/stars/Velocidex/velociraptor?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Velocidex/velociraptor?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Velocidex/velociraptor?style=flat-square&cacheSeconds=86400)

Website: https://www.velocidex.com

Maintainer: Velocidex Enterprises

License: AGPL 3.0

#### Beats
![GitHub stars](https://img.shields.io/github/stars/elastic/beats?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/elastic/beats?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/elastic/beats?style=flat-square&cacheSeconds=86400)

Website: https://www.elastic.co/products/beats

Maintainer: Elasticsearch B.V.

License: Apache v2 / Proprietary



## X.509 certificates monitoring

X.509 certificate monitoring systems provide means for identifying
network incidents through analysis of issued certificates. Monitoring
can be performed with checking for certificates issued for phishing
sites or with hunting of connections to websites for which blacklisted
certificates were issued.


### Evaluation

**Type:** Support

**Timeliness:** Excellent; near realtime.

**Accuracy:** Excellent; certificate monitoring provides information about actual certificates issued or encountered in the wild.

**Ease of use:** Good; data can be interpreted easily.

**Coverage:** Certificate Transparency (CT) provide coverage of all new certificates issued by main Certificate Authorities; other certificates are primarily coming from internet scans and their coverage vary between providers.

**Resources:** Good; exiting tools for using CT; exception: internet scanning requires significant resources.

**Scalability:** N/A

**Extensibility:** N/A; typically custom solutions.

**Completeness:** Fair; X.509 provide multiple details to pivot on but further correlation is usually required.


### Examples of tools

#### CIRCL Passive SSL (service)

Website: https://www.circl.lu/services/passive-ssl/

Maintainer: CIRCL

License: Unknown

#### crt.sh (service)

Website: https://crt.sh/

Maintainer: Sectigo Ltd.

License: Unknown

#### Cert Spotter
![GitHub stars](https://img.shields.io/github/stars/SSLMate/certspotter?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/SSLMate/certspotter?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/SSLMate/certspotter?style=flat-square&cacheSeconds=86400)

Website: https://github.com/SSLMate/certspotter

Maintainer: SSLmate

License: MPL 2.0

#### sensor-d4-tls-fingerprinting
![GitHub stars](https://img.shields.io/github/stars/D4-project/sensor-d4-tls-fingerprinting?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/D4-project/sensor-d4-tls-fingerprinting?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/D4-project/sensor-d4-tls-fingerprinting?style=flat-square&cacheSeconds=86400)

Website: https://github.com/D4-project/sensor-d4-tls-fingerprinting

Maintainer: CIRCL

License: MIT



## Vulnerability scanning

Vulnerability scanning systems are used to identify any vulnerabilities
in the monitored environment. Depending on tool, they can provide basic
information about services, but also give extended information about
identified problems. These includes for example information about
identified vulnerable services on particular ports, IP addresses or
Autonomous Systems.


### Evaluation

**Type:** Alerts.

**Timeliness:** Poor; depends on the scanning schedule; typically days or longer.

**Accuracy:** Poor; reports often need verification.

**Ease of use:** Good; large choice of COTS and open-source tools with various levels of sophistication.

**Coverage:** Monitoring of local infrastructure; in practice depends on which hosts are available for scanning.

**Resources:** Good; analyst's time is required to verify results of the automated tools; infrastructure is not significant unless large networks or the whole internet are scanned.

**Scalability:** Good.

**Extensibility:** Good; typically multiple ways to add new ways of checking particular vulnerabilities,

**Completeness:** Fair; depends on the tool, provides data on vulnerability and the scanned service.


### Examples of tools

#### OpenVas
![GitHub stars](https://img.shields.io/github/stars/greenbone/openvas?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/greenbone/openvas?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/greenbone/openvas?style=flat-square&cacheSeconds=86400)

Website: http://www.openvas.org/

Maintainer: Greenbone Networks GmbH

License: GPL 2.0
1G
#### Unfetter
![GitHub stars](https://img.shields.io/github/stars/unfetter-discover/unfetter?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/unfetter-discover/unfetter?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/unfetter-discover/unfetter?style=flat-square&cacheSeconds=86400)

Website: https://github.com/unfetter-discover/unfetter

Maintainer: NSA

License: CC0 1.0 Universal license

#### ZMap
![GitHub stars](https://img.shields.io/github/stars/zmap/zmap?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/zmap/zmap?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/zmap/zmap?style=flat-square&cacheSeconds=86400)

Website: https://github.com/zmap/zmap

Maintainer: The ZMap Project

License: Apache 2.0

#### nmap
![GitHub stars](https://img.shields.io/github/stars/nmap/nmap?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/nmap/nmap?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nmap/nmap?style=flat-square&cacheSeconds=86400)

Website: https://nmap.org

Maintainer: community

License: GPL 2.0 derived

#### masscan
![GitHub stars](https://img.shields.io/github/stars/robertdavidgraham/masscan?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/robertdavidgraham/masscan?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/robertdavidgraham/masscan?style=flat-square&cacheSeconds=86400)

Website: https://github.com/robertdavidgraham/masscan

Maintainer: individual

License: AGPL 3.0

#### Metasploit
![GitHub stars](https://img.shields.io/github/stars/rapid7/metasploit-framework?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/rapid7/metasploit-framework?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/rapid7/metasploit-framework?style=flat-square&cacheSeconds=86400)

Website: https://www.metasploit.com/

Maintainer: Rapid7

License: Different licenses depending on file

#### Nessus

_closed source_

Website: https://www.tenable.com/products/nessus

Vendor: Tenable

License: Proprietary

#### Google Tsunami
![GitHub stars](https://img.shields.io/github/stars/google/tsunami-security-scanner?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/google/tsunami-security-scanner?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/google/tsunami-security-scanner?style=flat-square&cacheSeconds=86400)


Website: https://github.com/google/tsunami-security-scanner

Maintainer : community

License: Apache License 2.0

## Automated spam collection

Spam collection systems help in gathering spam sent to the monitored
environment and, when equipped with analysis systems, give good insight
into current spam campaigns. Monitoring of real or decoy mailboxes in
the organization's domain can be a very relevant source of information
for detecting targeted attacks. This information is a starting for
identification of network incidents giving possible indicators of
compromise, including information about attachments, links, involved
malware, etc. However it also helps with prevention of network incidents
by, for example, constituting the basis for notification of targeted users.


### Evaluation

**Type:** Alerts.

**Timeliness:** Good; usually new campaigns can be caught with low delay.

**Accuracy:** Good; there is a risk of non-spam emails being received.

**Ease of use:** Fair; easy if tooling supports grouping and analysis; otherwise monitoring can be more time-consuming.

**Coverage:** Spam targeting domains and mailboxes of interest; for monitoring of opportunistic attacks, the size and diversity of the collection infrastructure determines if most of wide-scale campaigns will be detected.

**Resources:** Good; low effort, unless spam is analysed on a large scale.

**Scalability:** Good; possible use of multiple sensors, domains and mailboxes; there are diminishing results from building a large collection infrastructure; large amount of retained messages can cause non-negligible requirements for the storage.

**Extensibility:** N/A; tool-dependent.

**Completeness:** Good; header, body and attachments provide a lot of information.


### Examples of tools

#### SpamScope
![GitHub stars](https://img.shields.io/github/stars/SpamScope/spamscope?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/SpamScope/spamscope?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/SpamScope/spamscope?style=flat-square&cacheSeconds=86400)

Website: https://github.com/SpamScope/spamscope

Maintainer: individual

License: Apache 2.0



## Sandbox (automated systems for behavioural analysis)

Automated systems for malware behavioral analysis (malware sandboxes)
are used to provide information about the behaviour of systems after the opening
observed files, and as a result provide information about thei maliciousness. Depending on technologies sandboxes provide information about
network connections, used system libraries, modified registry items and
other behavioural data. Also, the behaviour is usually analysed to provide
information about malware families or variants. The sandbox systems can
be operated using own infrastructure or used as a service, provided by
many vendors, including free of charge bill plans.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Good; minutes or longer.

**Accuracy:** Poor; reports need verification; both false-positives and false-negatives are common.

**Ease of use:** Good; tools provide intuitive interfaces.

**Coverage:** Depends on the source of malware samples analysed; can vary from samples targeting a single organization to a large-scale lab with wide range of malware campaigns being analysed.

**Resources:** Fair; requires effort to understand and verify reports.

**Scalability:** Good; processing of a large number of samples requires an appropriate processing infrastructure and, more importantly, storage for behavioural reports.

**Extensibility:** Excellent; usually multiple ways of adapting behaviour and extending analytical capabilities.

**Completeness:** Good; behavioural reports contain a lot of details.


### Examples of tools

#### Cuckoo Sandbox
![GitHub stars](https://img.shields.io/github/stars/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)

Website: http://www.cuckoosandbox.org/

Maintainer: Cuckoo Foundation

License: GPL 3.0

#### app.any.run (service)

Website: https://app.any.run/

Maintainer: ANY.RUN

License: Unknown

#### cuckoo.cert.ee (service)

Website: https://cuckoo.cert.ee/

Maintainer: CERT.EE

License: Unknown

#### hybrid-analysis.com (service)

Website: https://www.hybrid-analysis.com/

Maintainer: CrowdStrike

License: Unknown

#### CAPE Sandbox
![GitHub stars](https://img.shields.io/github/stars/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)

Website: https://github.com/kevoreilly/CAPEv2

Maintainer: individual

License: Unknown

#### CAPE Sandbox (service)

Website: https://cape.contextis.com/

Maintainer: Context Information Security

License: Unknown



## Automated mobile malware analysis

Automated mobile malware analysis systems provide analyses similar to standard sandboxes and static analysis tools targeting desktop platforms. Most tooling focuses solely on the Android OS family. A majority of the off-the-shelf solutions that offer malware detection capability are online services. Local analysis often requires deploying a custom solution, for example based on existing emulators, and is rarely fully-automated with some human supervision involved.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Good; minutes or longer.

**Accuracy:** Poor; with exceptions, common automated analysis tools have high false-negative rate, since malware commonly evades detection; typically manual inspection by a human analyst is required to confirm if an application is harmless or not; for online services, the mechanism where community members can vote on the maliciousness of a sample might yield results that are significantly better than any automated analyses.

**Ease of use:** Good; web-based interfaces for browsing results are intuitive; other functionalities like advanced search and APIs can be more challenging.

**Coverage:** Depends on the source of malware samples analysed; samples are mostly collected from various public sources, including app markets; filtering samples that are relevant for the constituency might require manual work.

**Resources:** Fair; developing and deploying a sample collection mechanisms and processes can be challenging; initial triage of samples might require manual inspection; actual number of samples to fully analyse for a typical teams is usually no more than dozens per day, however their analysts time is required to interpret the results.

**Scalability:** N/A; a typical team will not deal with the number of samples that requires scaling of automated tools; when manual reverse engineering is needed, availability of human analysts might be a bottleneck.

**Extensibility:** Fair; online services often provide ability for rule-based threat hunting; more advanced modifications.

**Completeness:** Excellent; online tools provide detailed static and dynamic analysis results and often verdicts from AV scanners.


### Examples of tools

#### Androguard
![GitHub stars](https://img.shields.io/github/stars/androguard/androguard?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/androguard/androguard?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/androguard/androguard?style=flat-square&cacheSeconds=86400)

Website: https://github.com/androguard/androguard

Maintainer: individual

License: Apache 2.0

#### Androwarn
![GitHub stars](https://img.shields.io/github/stars/maaaaz/androwarn?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/maaaaz/androwarn?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/maaaaz/androwarn?style=flat-square&cacheSeconds=86400)

Website: https://github.com/maaaaz/androwarn

Maintainer: individual

License: LGPL 3.0

#### koodous.com (service)

Website: https://koodous.com/

Maintainer: Koodous Project

License: Unknown

#### APKLAB.io (service)

Website: https://www.apklab.io/

Maintainer: Avast

License: vetted researchers (free of charge)



## Automated static malware analysis

Automated static malware analysis systems help in the analysis of malicious
files without using dynamic analysis methods. The systems can operate
using binaries and memory dumps in order to extract static configuration
of malware. Their functionality can be extended by equipping it with the YARA
signature matching.


### Evaluation

**Type:** Alert, support.

**Timeliness:** Good; seconds to minutes.

**Accuracy:** Good; quality of results depends on the rules and methods used.

**Ease of use:** Fair; some of the tools can require expertise in malware analysis to operate.

**Coverage:** Depends on the source of malware samples analysed; can vary from samples targeting a single organization to a large-scale lab with a wide range of malware campaigns being analysed.

**Resources:** Good.

**Scalability:** Good; processing of a large number of samples requires appropriate processing infrastructure.

**Extensibility:** Good; tools often are rule-based, have plugin mechanisms or can be arranged in different processing workflows.

**Completeness:** N/A; tool-dependent; some of the tools can provide important indicators that would be impossible to obtain otherwise without manual analysis of malware.


### Examples of tools

#### CAPE Sandbox
![GitHub stars](https://img.shields.io/github/stars/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/kevoreilly/CAPEv2?style=flat-square&cacheSeconds=86400)

Website: https://github.com/kevoreilly/CAPEv2

Maintainer: individual

License: Unknown

#### CAPE Sandbox (service)

Website: https://cape.contextis.com/

Maintainer: Context Information Security

License: Unknown

#### RATDecoders
![GitHub stars](https://img.shields.io/github/stars/kevthehermit/RATDecoders?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/kevthehermit/RATDecoders?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/kevthehermit/RATDecoders?style=flat-square&cacheSeconds=86400)

Website: https://github.com/kevthehermit/RATDecoders

Maintainer: individual

License: MIT

#### malwareconfig.com (service)

Website: https://malwareconfig.com/

Maintainer: individual

License: Unknown

#### MalConfScan
![GitHub stars](https://img.shields.io/github/stars/JPCERTCC/MalConfScan?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/JPCERTCC/MalConfScan?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/JPCERTCC/MalConfScan?style=flat-square&cacheSeconds=86400)

Website: https://github.com/JPCERTCC/MalConfScan

Maintainer: JPCERT Coordination Center

License: BSD 3-Clause

#### Malduck
![GitHub stars](https://img.shields.io/github/stars/CERT-Polska/malduck?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/CERT-Polska/malduck?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/CERT-Polska/malduck?style=flat-square&cacheSeconds=86400)

Website: https://github.com/CERT-Polska/malduck

Maintainer: CERT Polska

License: GPL 3.0



## Leak monitoring

Leak monitoring systems provide means for detection of information
leakage by scanning possible hosting sources of leaked information. This
includes pastes services, but also other sources such as code
repositories or cloud services.


### Evaluation

**Type:** Alerts.

**Timeliness:** Fair; depends on data sources; can vary from seconds to days.

**Accuracy:** Poor; matching is typically done by regular expressions and yield many false positives.

**Ease of use:** Good; tools provide convenient interfaces to browse the data.

**Coverage:** Depends on the sources; usually new content is matched against a predefined set of rules and only data relevant to the constituency are processed.

**Resources:** Good; alerts need manual verification but their number is usually not very high.

**Scalability:** N/A

**Extensibility:** Fair; typically, tools support adding new data feeds to monitor.

**Completeness:** Poor: data dumps often come with little context and require further analysis.


### Examples of tools

#### AIL framework - Analysis Information Leak framework
![GitHub stars](https://img.shields.io/github/stars/CIRCL/AIL-framework?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/CIRCL/AIL-framework?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/CIRCL/AIL-framework?style=flat-square&cacheSeconds=86400)

Website: https://github.com/CIRCL/AIL-framework

Maintainer: CIRCL

License: AGPL 3.0

#### git-secrets
![GitHub stars](https://img.shields.io/github/stars/awslabs/git-secrets?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/awslabs/git-secrets?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/awslabs/git-secrets?style=flat-square&cacheSeconds=86400)

Website: https://github.com/awslabs/git-secrets

Maintainer: Amazon

License: Apache 2.0

#### KeyNuker
![GitHub stars](https://img.shields.io/github/stars/tleyden/keynuker?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/tleyden/keynuker?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/tleyden/keynuker?style=flat-square&cacheSeconds=86400)

Website: https://github.com/tleyden/keynuker

Maintainer: individual

License: Apache 2.0



## Media/news monitoring

Media/news monitoring systems help in obtaining operational information
from traditional news sources, such as newspapers, but also blogs and
social media services, for example Twitter. The latter can be specially
helpful, as many information security researchers post current
information there, before some longer forms are filled in on other platforms.


### Evaluation

**Type:** Alerts.

**Timeliness:** Fair; varies from minutes to days.

**Accuracy:** Fair; credibility depends on the source.

**Ease of use:** Excellent; News aggregators/monitors have intuitive interfaces.

**Coverage:** Depends on the sources monitored; can cover majority of traditional outlets, thematic blogs and Twitter.

**Resources:** Fair; requires time to read summaries of articles and do further research in some cases.

**Scalability:** N/A

**Extensibility:** Fair; typically, tools support adding new feeds of information and configuring how they are processed.

**Completeness:** Fair; depends on the source and the item; can be very ambiguous or may contain sufficient technical information.


### Examples of tools

#### Taranis
![GitHub stars](https://img.shields.io/github/stars/NCSC-NL/taranis3?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/NCSC-NL/taranis3?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/NCSC-NL/taranis3?style=flat-square&cacheSeconds=86400)

Website: https://github.com/NCSC-NL/taranis3

Maintainer: NCSC-NL

License: EUPL v1.2

#### Europe Media Monitor (service)

Website: https://emm.newsbrief.eu/overview.html

Maintainer: European Commission's Joint Research Centre

License: Unknown



## Client honeypots

Client honeypots are systems designed to mimic the behaviour of a client application in order to detect malicious behaviour of servers. In general, the honeypot interacts with a probed server, and is then analysed to uncover any malicious activity. Different applications can be monitored, however most common are web browsers. As with server honeypots, client honeypots can be high-interaction or low-interaction. The former uses environments similar to those used by standard clients in order to provide similar conditions. This is especially useful during the analysis of Exploit Kits, as such systems perform machine fingerprint and could not operate in systems with limited capabilities. The downsides of this type of honeypot are that it is harder to deploy than the low interaction ones and it requires resources for running virtual machines with the mimicked operating systems. The low interaction honeypots provide limited capabilities comparing to the high interaction type, however they are easier to deploy and require less resources per mimicked client. Usually, a honeypot simulates some basic functions of the client, then the responses from the server are analysed in search of known traces of malicious behaviour. The downside of this approach is that some unknown attacks could remain undetected, as for example with the already mentioned Exploit Kits.


### Evaluation

**Type:** Alerts, support.

**Timeliness:** Poor; varied, depends on scan frequency; typically not quicker than hours.

**Accuracy:** Fair; depends on the detection method used by the tool: some systems (especially high-interaction ones) can be prone to false positives; low-interaction honeypots may not provide correct results at all, leading to false negatives.

**Ease of use:** Poor; expertise is needed both to configure and to interpret data obtained from client honeypots.

**Coverage:** Depends on the set of pages selected from scanning: can vary from own infrastructure, sites likely visited by the constituency, entire TLD or more.

**Resources:** High; alerts need verification; interpretation of output can take time.

**Scalability:** Good; scanning can be distributed.

**Extensibility:** N/A; tool-dependent.

**Completeness:** Fair; in principle can provide complete details of the interaction with a server; actual level of details depends on a tool, with low-interaction honeypots providing more details in general.


### Examples of tools

#### Thug
![GitHub stars](https://img.shields.io/github/stars/buffer/thug?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/buffer/thug?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/buffer/thug?style=flat-square&cacheSeconds=86400)

Website: https://github.com/buffer/thug

Maintainer: individual

License: GPL 2.0

#### YALIH
![GitHub stars](https://img.shields.io/github/stars/Masood-M/yalih?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Masood-M/yalih?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Masood-M/yalih?style=flat-square&cacheSeconds=86400)

Website: https://github.com/Masood-M/yalih

Maintainer: individual

License: Apache 2.0

#### miniC
![GitHub stars](https://img.shields.io/github/stars/Masood-M/miniC?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/Masood-M/miniC?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Masood-M/miniC?style=flat-square&cacheSeconds=86400)

Website: https://github.com/Masood-M/miniC

Maintainer: individual

License: GPL 3.0

#### Cuckoo Sandbox
![GitHub stars](https://img.shields.io/github/stars/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/cuckoosandbox/cuckoo?style=flat-square&cacheSeconds=86400)

Website: http://www.cuckoosandbox.org/

Maintainer: Cuckoo Foundation

License: GPL 3.0



## Server honeypots

Server honeypots are systems mimicking servers to detect and analyse malicious behaviour of clients. A plethora of different honeypots exists covering multiple services, including general purpose servers, web servers, FTP, databases, VoIP, SCADA etc. Generally, server honeypots open ports for popular services and analyse received data. This approach provides an opportunity to detect scanning activities, exploit attempts, as well as other behavior. The level of interaction can differ between honeypots, dividing them into low and high interaction groups. The former provides environment to emulate behaviour of a service, thus providing limited capabilities compared to real server. However the deployment is relatively easy and resources needed for running a single instance are lower than in a high interaction honeypot. High interaction honeypots usually are deployed based on real servers, giving detailed information about the attacker's behaviour, which is not available in low interaction systems. However their resources requirement is higher and without appropriate mechanisms they are prone to being compromised by the attacker.


### Evaluation

**Type:** Alerts.

**Timeliness:** Excellent; realtime.

**Accuracy:** Fair; while there should be no legitimate connections to honeypots, in practice there might be a lot of irrelevant activity from scanners or misconfigured devices; most honeypots can be identified by attackers or might have faults in service emulation, which might prevent collection of essential attack details.

**Ease of use:** Fair; interpretation of the output and finding relevant information requires expertise.

**Coverage:** Depends on the range of exposed services, deployment model (internal network or external address) and advertising (to make the honeypot discoverable).

**Resources:** Analysis of details of attacks can be time-intensive; no human resources needed in a fully automated setup, however honeypots provide much less value then.

**Scalability:** Good; scales with the number of sensors; there are diminishing results from building a large sensor infrastructure (both in internal and external deployment models).

**Extensibility:** N/A; tool-dependent; there exist multi-service honeypot that offer very good plugin support.

**Completeness:** Fair; typically complete details of a network session but at the same time fundamentally limited by the level of interaction that the honeypot can offer to attackers.


### Examples of tools

#### Dionaea
![GitHub stars](https://img.shields.io/github/stars/DinoTools/dionaea?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/DinoTools/dionaea?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/DinoTools/dionaea?style=flat-square&cacheSeconds=86400)

Website: https://github.com/DinoTools/dionaea

Maintainer: individual

License: GPL 2.0+ / GPL 3.0+

#### Snare
![GitHub stars](https://img.shields.io/github/stars/mushorg/snare?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/mushorg/snare?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/mushorg/snare?style=flat-square&cacheSeconds=86400)

Website: https://github.com/mushorg/snare

Maintainer: MushMush Foundation

License: GPL 3.0

#### Cowrie
![GitHub stars](https://img.shields.io/github/stars/cowrie/cowrie?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/cowrie/cowrie?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/cowrie/cowrie?style=flat-square&cacheSeconds=86400)

Website: https://www.cowrie.org/

Maintainer: Cowrie Project

License: BSD 3-Clause

#### Conpot
![GitHub stars](https://img.shields.io/github/stars/mushorg/conpot?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/mushorg/conpot?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/mushorg/conpot?style=flat-square&cacheSeconds=86400)

Website: https://github.com/mushorg/conpot

Maintainer: MushMush Foundation

License: GPL 2.0

#### T-Pot
![GitHub stars](https://img.shields.io/github/stars/dtag-dev-sec/tpotce?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/dtag-dev-sec/tpotce?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/dtag-dev-sec/tpotce?style=flat-square&cacheSeconds=86400)

Website: https://github.com/dtag-dev-sec/tpotce

Maintainer: Telekom Security

License: GPL 3.0

#### Heralding
![GitHub stars](https://img.shields.io/github/stars/johnnykv/heralding?style=flat-square&cacheSeconds=86400)
![GitHub last commit](https://img.shields.io/github/last-commit/johnnykv/heralding?style=flat-square&cacheSeconds=86400)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/johnnykv/heralding?style=flat-square&cacheSeconds=86400)

Website: https://github.com/johnnykv/heralding

Maintainer: individual

License: GPL 3.0



## Monitoring of sector specific technologies

Different sectors (for example aviation, health, etc) have specific software and hardware that needs to be monitored for intrusions and other suspicious activity. However in practice, the measures used for detection fall into one of the following categories: 1) OT networks, where measures are described in "Monitoring specific to industrial control systems", or 2) IT networks, where majority of measures described above are applicable.

