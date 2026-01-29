&lt;div align="center"&gt;

![Terminal Glitch](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdW12anZ4anZ4anZ4anZ4anZ4anZ4anZ4anZ4/26xBI73gWquCBBCDe/giphy.gif)

# MODERN HACKING TOOLS (FOR BUG HUNTER) 2025-2026

**Curated. Verified. Lethal.**
*The complete collection of active hacking tools for the modern era.*

[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Maintenance](https://img.shields.io/badge/maintained-YES-00ff00?style=flat-square)](https://github.com/paundrapf/BUG-HUNTER-TOOLS)
[![Tools](https://img.shields.io/badge/count-200%2B-ff00ff?style=flat-square)](https://github.com/paundrapf/BUG-HUNTER-TOOLS)

&lt;/div&gt;

---

## ⚡ Criteria
We don't do "abandonware". Everything here is:
1.  **Active:** Last commit 2024-2026.
2.  **Functional:** No critical bugs ignored for &gt;6 months.
3.  **Modern:** Works with current stacks (Cloud, K8s, Web3).

---

## 📂 Index

*   [Web Application Security](#-web-application-security)
*   [Network Security](#-network-security)
*   [API Security](#-api-security-testing)
*   [Mobile Security](#-mobile-application-security)
*   [Cloud Security](#-cloud-security)
*   [Container & Kubernetes](#-container--kubernetes-security)
*   [Recon & OSINT](#-reconnaissance--osint)
*   [Exploitation Frameworks](#-exploitation-frameworks)
*   [Password Cracking](#-password-security--cracking)
*   [Bug Bounty Automation](#-bug-bounty-automation)
*   [Code Analysis (SAST/DAST)](#-sastdast--code-analysis)
*   [SSL/TLS](#-ssltls-security-testing)
*   [CTF & Wargames](#-ctf--wargame-tools)
*   [Active Directory](#-active-directory--windows-security)
*   [Web3 & Blockchain](#-web3blockchain-security)
*   [IoT & Firmware](#-iot-security)
*   [Wireless (WiFi/BLE/SDR)](#-wireless-security)
*   [Automotive](#-automotive-security)
*   [Hardware Hacking](#-hardware-security)
*   [Red Team & C2](#-red-team-c2-frameworks)
*   [Digital Forensics](#-digital-forensics)
*   [Social Engineering](#-social-engineering--phishing)
*   [Steganography](#-steganography)
*   [Malware Analysis](#-malware-analysis)
*   [Threat Intel](#-threat-intelligence)
*   [VPN/Proxy & Anonymity](#-vpnproxy--anonymity)
*   [Log Analysis & SIEM](#-log-analysis--siem)
*   [Reporting](#-pentest-reporting)
*   [AI/ML Security](#-aiml-security)
*   [Reverse Shell & Webshell](#-reverse-shell--webshell)
*   [Privilege Escalation](#-privilege-escalation)
*   [Post-Exploitation](#-post-exploitation)
*   [Resources & Wordlists](#-resources--wordlists)

---

## 🌐 Web Application Security

### Scanners & Injection
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[DalFox](https://github.com/hahwul/dalfox)** | XSS scanner & parameter analyzer (Go). | Jan 2026 |
| **[FinDOM-XSS](https://github.com/dwisiswant0/findom-xss)** | Fast DOM-based XSS finder. | Active |
| **[SQLMap](https://github.com/sqlmapproject/sqlmap)** | Automatic SQL injection tool. | Jan 2025 |
| **[Commix](https://github.com/commixproject/commix)** | Command injection exploitation. | Active |
| **[SSRF-Scanner](https://github.com/Dancas93/SSRF-Scanner)** | Comprehensive SSRF scanner. | Active |
| **[LFIHunt](https://github.com/Chocapikk/LFIHunt)** | LFI scanner & exploitation. | Active |
| **[OpenRedirector](https://github.com/0xKayala/OpenRedirector)** | Open Redirect vulnerability scanner. | Active |
| **[Smuggler](https://github.com/defparam/smuggler)** | HTTP Request Smuggling/Desync tool. | Active |
| **[Wapiti](https://github.com/wapiti-scanner/wapiti)** | Black-box scanner (XSS, SQLi, RCE, XXE). | Active |
| **[Nikto](https://github.com/sullo/nikto)** | Classic web server scanner. | Dec 2025 |

### Recon & Discovery
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Subfinder](https://github.com/projectdiscovery/subfinder)** | Fast passive subdomain enumeration. | Dec 2025 |
| **[Amass](https://github.com/owasp-amass/amass)** | In-depth attack surface mapping. | Sep 2025 |
| **[Findomain](https://github.com/Findomain/Findomain)** | Fastest cross-platform enumerator. | Jul 2025 |
| **[Knockpy](https://github.com/guelfoweb/knock)** | Subdomain enum with async support. | Oct 2025 |
| **[AlterX](https://github.com/projectdiscovery/alterx)** | Subdomain wordlist generator (DSL). | Active |
| **[DNSGen](https://github.com/AlephNullSK/dnsgen)** | DNS name permutation. | Active |
| **[ShuffleDNS](https://github.com/projectdiscovery/shuffledns)** | Fast DNS resolver wrapper. | Active |
| **[PureDNS](https://github.com/d3mondev/puredns)** | Domain resolver & bruteforcing. | Active |
| **[dnsx](https://github.com/projectdiscovery/dnsx)** | Multi-purpose DNS toolkit. | Active |
| **[ASNMap](https://github.com/projectdiscovery/asnmap)** | Org network range mapping. | Active |

### Fuzzing & Parameters
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Gobuster](https://github.com/OJ/gobuster)** | Directory/file brute-forcer. | Jan 2026 |
| **[Feroxbuster](https://github.com/epi052/feroxbuster)** | Recursive content discovery (Rust). | Oct 2025 |
| **[Dirsearch](https://github.com/maurosoria/dirsearch)** | Web path scanner. | Dec 2025 |
| **[FFUF](https://github.com/ffuf/ffuf)** | Fast web fuzzer (Go). | Apr 2025 |
| **[Arjun](https://github.com/s0md3v/Arjun)** | HTTP parameter discovery. | Feb 2025 |
| **[ParamSpider](https://github.com/devanshbatham/ParamSpider)** | Mine parameters from web archives. | Active |
| **[Gxss](https://github.com/KathanP19/Gxss)** | Reflected parameter finder. | Active |

### Crawlers & CMS
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Katana](https://github.com/projectdiscovery/katana)** | Next-gen crawling framework. | Active |
| **[Waybackurls](https://github.com/tomnomnom/waybackurls)** | Fetch URLs from Wayback Machine. | Active |
| **[GAU](https://github.com/lc/gau)** | GetAllUrls - Fetch from multiple sources. | Active |
| **[WPScan](https://github.com/wpscanteam/wpscan)** | WordPress vulnerability scanner. | Active |
| **[Droopescan](https://github.com/SamJoan/droopescan)** | CMS vulnerability scanner. | Active |
| **[WhatWeb](https://github.com/urbanadventurer/WhatWeb)** | Technology detection scanner. | Active |

---

## 📡 Network Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Nmap](https://github.com/nmap/nmap)** | Network discovery & security auditing. | Feb 2025 |
| **[RustScan](https://github.com/RustScan/RustScan)** | Modern port scanner (Rust). | Active |
| **[Masscan](https://github.com/robertdavidgraham/masscan)** | Mass IP port scanner. | Active |
| **[Naabu](https://github.com/projectdiscovery/naabu)** | Fast port scanner (Go). | Nov 2025 |

---

## 🔌 API Security Testing

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Kiterunner](https://github.com/assetnote/kiterunner)** | API endpoint discovery tool. | Active |
| **[InQL](https://github.com/doyensec/inql)** | GraphQL testing for Burp Suite. | Active |

---

## 📱 Mobile Application Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** | Mobile Security Framework. | Active |
| **[APKTool](https://github.com/iBotPeaches/Apktool)** | Reverse engineering Android APKs. | Active |
| **[JADX](https://github.com/skylot/jadx)** | Dex to Java decompiler. | Active |
| **[Frida](https://github.com/frida/frida)** | Dynamic instrumentation toolkit. | Active |
| **[Objection](https://github.com/sensepost/objection)** | Runtime mobile exploration. | Active |

---

## ☁️ Cloud Security

### AWS & Multi-Cloud
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | AWS security best practices. | Dec 2025 |
| **[CloudBrute](https://github.com/0xsha/CloudBrute)** | Cloud infrastructure enumeration (AWS/GCS/Azure). | Active |
| **[Pacu](https://github.com/RhinoSecurityLabs/pacu)** | AWS exploitation framework. | Active |
| **[PMapper](https://github.com/nccgroup/PMapper)** | AWS IAM privilege escalation finder. | Active |
| **[S3Scanner](https://github.com/sa7mon/S3Scanner)** | S3 bucket discovery & testing. | Active |

---

## 📦 Container & Kubernetes Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Kube-Hunter](https://github.com/aquasecurity/kube-hunter)** | Kubernetes pen-testing tool. | Active |
| **[KubeBench](https://github.com/aquasecurity/kube-bench)** | CIS Kubernetes Benchmark. | Active |
| **[KubeHound](https://github.com/DataDog/KubeHound)** | Attack path graph generation. | Active |
| **[IceKube](https://github.com/withsecurelabs/icekube)** | K8s attack path analysis. | Active |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Container/FS/Git scanner. | Dec 2025 |
| **[Docker-Bench](https://github.com/docker/docker-bench-security)** | CIS Docker Benchmark. | Active |
| **[Clair](https://github.com/quay/clair)** | Container vulnerability analyzer. | Active |

---

## 🕵️ Reconnaissance & OSINT

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[theHarvester](https://github.com/laramies/theHarvester)** | Email/subdomain harvester. | Dec 2025 |
| **[SpiderFoot](https://github.com/smicallef/spiderfoot)** | OSINT automation platform. | Active |
| **[Amass](https://github.com/owasp-amass/amass)** | Attack surface mapping. | Sep 2025 |
| **[Shodan](https://github.com/achillean/shodan-python)** | IoT search engine library. | Active |
| **[Sherlock](https://github.com/sherlock-project/sherlock)** | Social media account hunter. | Active |
| **[Holehe](https://github.com/megadose/holehe)** | Check if email is attached to social media. | Active |

---

## 💥 Exploitation Frameworks

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Metasploit](https://github.com/rapid7/metasploit-framework)** | The standard framework. | Jan 2026 |
| **[ExploitDB](https://gitlab.com/exploit-database/exploitdb)** | Archive of public exploits. | Active |
| **[BeEF](https://github.com/beefproject/beef)** | Browser Exploitation Framework. | Active |
| **[Empire](https://github.com/BC-SECURITY/Empire)** | PowerShell/Python post-exploit. | Active |

---

## 🔐 Password Security & Cracking

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Hashcat](https://github.com/hashcat/hashcat)** | World's fastest cracker. | Nov 2025 |
| **[John the Ripper](https://github.com/openwall/john)** | Password cracker. | Jan 2025 |
| **[Hydra](https://github.com/vanhauser-thc/thc-hydra)** | Network logon cracker. | Nov 2025 |
| **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)** | Network Swiss Army knife. | Active |
| **[Impacket](https://github.com/fortra/impacket)** | Python network protocols. | Oct 2025 |

---

## 🐛 Bug Bounty Automation

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Nuclei](https://github.com/projectdiscovery/nuclei)** | Template-based scanner. | Active |
| **[Nuclei-Templates](https://github.com/projectdiscovery/nuclei-templates)** | Curated templates. | Active |
| **[HTTPX](https://github.com/projectdiscovery/httpx)** | Multi-purpose HTTP toolkit. | Jan 2026 |
| **[Notify](https://github.com/projectdiscovery/notify)** | Notification framework. | Active |
| **[Interactsh](https://github.com/projectdiscovery/interactsh)** | OOB interaction server/client. | Active |
| **[Katana](https://github.com/projectdiscovery/katana)** | Web crawler for automation. | Active |
| **[Chaos](https://github.com/projectdiscovery/chaos-client)** | DNS recon platform. | Active |
| **[Uncover](https://github.com/projectdiscovery/uncover)** | Search engine host discovery. | Active |
| **[CVEMap](https://github.com/projectdiscovery/cvemap)** | CVE navigator. | Active |
| **[ReconFTW](https://github.com/six2dez/reconftw)** | Full recon automation. | Active |
| **[Osmedeus](https://github.com/j3ssie/osmedeus)** | Offensive security framework. | Active |

---

## 📊 SAST/DAST & Code Analysis

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Semgrep](https://github.com/semgrep/semgrep)** | Polyglot static analysis. | Active |
| **[SonarQube](https://github.com/SonarSource/sonarqube)** | Code quality inspection. | Active |
| **[Bandit](https://github.com/PyCQA/bandit)** | Python security linter. | Active |
| **[Brakeman](https://github.com/presidentbeef/brakeman)** | Rails security scanner. | Active |
| **[Gosec](https://github.com/securego/gosec)** | Golang security checker. | Active |
| **[GitLeaks](https://github.com/gitleaks/gitleaks)** | Detect hardcoded secrets. | Nov 2025 |
| **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** | Find creds in Git repos. | Dec 2025 |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Container, Git repo, IaC scanner. | Dec 2025 |
| **[Kics](https://github.com/Checkmarx/kics)** | IaC vulnerability scanner. | Active |
| **[TFSec](https://github.com/aquasecurity/tfsec)** | Terraform code scanner. | Active |

---

## 🔎 SSL/TLS Security Testing

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Testssl.sh](https://github.com/testssl/testssl.sh)** | Command line TLS/SSL tester. | Active |
| **[SSLyze](https://github.com/nabla-c0d3/sslyze)** | Fast scanning library. | Aug 2025 |
| **[SSLScan](https://github.com/rbsec/sslscan)** | Fast SSL/TLS scanner. | Active |

---

## 🚩 CTF & Wargame Tools

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Pwntools](https://github.com/Gallopsled/pwntools)** | Exploit dev library. | Active |
| **[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)** | ROP gadget finder. | Active |
| **[pwndbg](https://github.com/pwndbg/pwndbg)** | GDB exploit enhancement. | Active |
| **[GEF](https://github.com/hugsy/gef)** | GDB Enhanced Features. | Active |
| **[Radare2](https://github.com/radareorg/radare2)** | Reversing framework. | Active |
| **[Ghidra](https://github.com/NationalSecurityAgency/ghidra)** | Reversing suite (NSA). | Active |

---

## 🏢 Active Directory & Windows Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[BloodHound](https://github.com/SpecterOps/BloodHound)** | AD attack path analysis. | Dec 2025 |
| **[SharpHound](https://github.com/BloodHoundAD/SharpHound)** | BloodHound C# ingestor. | Active |
| **[BloodHound.py](https://github.com/fox-it/BloodHound.py)** | Python-based ingestor for BloodHound. | Active |
| **[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)** | Network Swiss Army knife for AD. | Active |
| **[Impacket](https://github.com/fortra/impacket)** | Python classes for network protocols. | Oct 2025 |
| **[Responder](https://github.com/lgandx/Responder)** | LLMNR, NBT-NS, MDNS poisoner. | Active |
| **[Kerbrute](https://github.com/ropnop/kerbrute)** | Kerberos bruteforce. | Active |
| **[Rubeus](https://github.com/GhostPack/Rubeus)** | Raw Kerberos interaction. | Active |
| **[Certipy](https://github.com/ly4k/Certipy)** | AD Certificate Services abuse. | Active |
| **[PetitPotam](https://github.com/topotam/PetitPotam)** | Coerce auth attacks. | Active |

---

## ⛓️ Web3/Blockchain Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Slither](https://github.com/crytic/slither)** | Solidity static analysis. | Active |
| **[Mythril](https://github.com/ConsenSys/mythril)** | EVM security analysis. | Active |
| **[Halmos](https://github.com/a16z/halmos)** | Symbolic testing tool. | Aug 2025 |
| **[Echidna](https://github.com/crytic/echidna)** | Smart contract fuzzer. | Active |
| **[Medusa](https://github.com/crytic/medusa)** | Parallelized fuzzer. | Active |
| **[Foundry](https://github.com/foundry-rs/foundry)** | Ethereum dev framework. | Jan 2026 |
| **[Hardhat](https://github.com/NomicFoundation/hardhat)** | Ethereum dev environment. | Active |
| **[Eth Security Toolbox](https://github.com/trailofbits/eth-security-toolbox)** | Docker container with Trail of Bits tools. | Active |
| **[Building Secure Contracts](https://github.com/crytic/building-secure-contracts)** | Guidelines and training materials. | Active |
| **[fuzz-utils](https://github.com/crytic/fuzz-utils)** | Generate Foundry tests from fuzzer corpus. | Active |

---

## 📟 IoT Security

### Firmware Analysis
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Binwalk](https://github.com/ReFirmLabs/binwalk)** | Firmware extractor. | Oct 2024 |
| **[FACT_core](https://github.com/fkie-cad/FACT_core)** | Firmware comparison tool. | Active |
| **[Firmadyne](https://github.com/attify/firmware-analysis-toolkit)** | Firmware emulation. | Active |
| **[EMBA](https://github.com/e-m-b-a/emba)** | Firmware security analyzer. | Active |
| **[EMBArk](https://github.com/e-m-b-a/embark)** | Enterprise firmware scanning environment. | Active |
| **[Unblob](https://github.com/onekey-sec/unblob)** | Modern extraction suite. | Active |
| **[Firmwalker](https://github.com/craigz28/firmwalker)** | Script for firmware analysis. | Active |

### IoT Penetration Testing
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[PENIOT](https://github.com/yakuza8/peniot)** | IoT penetration tester. | Active |
| **[IoTGoat](https://github.com/OWASP/IoTGoat)** | Deliberately insecure IoT firmware. | Active |

---

## 📡 Wireless Security

### WiFi Security
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)** | WiFi auditing suite. | Active |
| **[WiFi Scanner](https://github.com/RaheesAhmed/wifi_scanner)** | Rust-based scanner. | Apr 2025 |

### Bluetooth Security
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Blue-sec](https://github.com/irfan-sec/Blue-sec)** | Bluetooth hacking and security. | Nov 2025 |
| **[Bluescan](https://github.com/DasSecurity-HatLab/bluescan)** | Powerful Bluetooth scanner. | Active |
| **[btlescan](https://github.com/ztroop/btlescan)** | BTLE/Bluetooth Scanner. | Mar 2024 |
| **[CaringCaribou](https://github.com/CaringCaribou/caringcaribou)** | Car security exploration for CAN bus. | Aug 2024 |

### RFID/NFC Security
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Proxmark3](https://github.com/RfidResearchGroup/proxmark3)** | Powerful general purpose RFID tool. | Sep 2025 |
| **[ChameleonMini](https://github.com/emsec/ChameleonMini)** | Portable NFC security analysis tool. | Active |
| **[ChameleonMini-rebooted](https://github.com/iceman1001/ChameleonMini-rebooted)** | Fork for RevE Rebooted hardware. | Active |

### SDR (Software Defined Radio)
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[HackRF](https://github.com/greatscottgadgets/hackrf)** | SDR peripheral for transmission/reception. | Active |
| **[RTL-SDR](https://github.com/osmocom/rtl-sdr)** | Cheap SDR receiver. | Active |
| **[YardStick One](https://github.com/greatscottgadgets/yardstick)** | Sub-1 GHz wireless transceiver. | Active |

---

## 🚗 Automotive Security

### CAN Bus Tools
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[can-utils](https://github.com/linux-can/can-utils)** | Linux CAN utilities. | Active |
| **[SavvyCAN](https://github.com/collin80/SavvyCAN)** | CAN bus analysis. | May 2025 |
| **[CANalyzat0r](https://github.com/schutzwerk/CANalyzat0r)** | Security analysis for proprietary car protocols. | Active |
| **[CaringCaribou](https://github.com/CaringCaribou/caringcaribou)** | Car security exploration for CAN bus. | Aug 2024 |
| **[CANToolz](https://github.com/CANToolz/CANToolz)** | Black-box CAN network analysis. | Active |

### Simulators
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[ICSim](https://github.com/zombieCraig/ICSim)** | Instrument Cluster Simulator. | Active |
| **[UDSim](https://github.com/zombieCraig/UDSim)** | Unified Diagnostic Services Simulator. | Active |
| **[GearGoat](https://github.com/ine-labs/GearGoat)** | Car Vulnerabilities Simulator. | May 2025 |

### Car Hacking Toolkits
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[CarHackingTools](https://github.com/jgamblin/CarHackingTools)** | Collection of common car hacking tools. | Aug 2023 |
| **[Carpunk](https://github.com/souravbaghz/Carpunk)** | CAN Injection Toolkit. | Active |

### OBD-II Tools
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[python-OBD](https://github.com/brendan-w/python-OBD)** | Python module for OBD-II vehicle diagnostics. | Active |
| **[SwiftOBD2](https://github.com/kkonteh97/SwiftOBD2)** | Swift OBD2 real-time vehicle diagnostics. | Feb 2024 |

---

## 🔧 Hardware Security

### Hardware Analysis Tools
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Bus Pirate](https://github.com/BusPirate/Bus_Pirate)** | Universal serial interface. | Active |
| **[HydraBus](https://github.com/hydrabus/hydrabus)** | Open source multi-tool hardware. | Active |
| **[Glasgow](https://github.com/GlasgowEmbedded/glasgow)** | Tool for exploring and debugging digital interfaces. | Active |
| **[ChipWhisperer](https://github.com/newaetech/chipwhisperer)** | Side-channel attack tool. | Active |

### JTAG/UART Tools
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[JTAGULATOR](https://github.com/grandideastudio/jtagulator)** | Detects JTAG pinouts fast. | Active |
| **[Bus Blaster](https://github.com/BusPirate/Bus_Pirate)** | JTAG debugger. | Active |
| **[OpenOCD](https://github.com/openocd-org/openocd)** | On-chip debugger. | Active |

---

## 🎯 Red Team C2 Frameworks

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Sliver](https://github.com/BishopFox/sliver)** | Adversary emulation. | Active |
| **[Havoc](https://github.com/HavocFramework/Havoc)** | Modern post-exploit C2. | Active |
| **[Mythic](https://github.com/its-a-feature/Mythic)** | Multi-platform C2. | Active |
| **[Covenant](https://github.com/cobbr/Covenant)** | .NET C2 framework. | Active |
| **[HardHat C2](https://github.com/DragoQCC/CrucibleC2)** | Cross-platform C# C2 framework. | Active |
| **[Exploration C2](https://github.com/maxDcb/C2TeamServer)** | Modular C2 framework (C++ TeamServer + Python Client). | Active |

---

## 🔍 Digital Forensics

### Memory Forensics
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Volatility3](https://github.com/volatilityfoundation/volatility3)** | Advanced memory forensics framework. | Active |
| **[Volatility](https://github.com/volatilityfoundation/volatility)** | Volatile memory extraction utility (legacy). | Archived |

### Disk Forensics
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Autopsy](https://github.com/sleuthkit/autopsy)** | Digital forensics platform. | Active |
| **[The Sleuth Kit](https://github.com/sleuthkit/sleuthkit)** | Library for disk forensics. | Active |

### Incident Response
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[TheHive](https://github.com/TheHive-Project/TheHive)** | Security incident response platform. | Jul 2025 |
| **[Cortex](https://github.com/TheHive-Project/Cortex)** | Observable analysis engine. | Nov 2025 |

### Network Forensics
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Wireshark](https://github.com/wireshark/wireshark)** | Network protocol analyzer. | Active |
| **[Zeek](https://github.com/zeek/zeek)** | Network security monitor. | Active |

---

## 🎣 Social Engineering & Phishing

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[GoPhish](https://github.com/gophish/gophish)** | Phishing framework. | Active |
| **[SET](https://github.com/trustedsec/social-engineer-toolkit)** | Social-Engineer Toolkit. | Active |

---

## 🖼️ Steganography

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Steghide](https://github.com/StegHigh/steghide-bak)** | Hide data in image/audio. | Active |
| **[Stegseek](https://github.com/RickdeJager/stegseek)** | Lightning fast steghide cracker. | Active |
| **[zsteg](https://github.com/zed-0xff/zsteg)** | Detect hidden data in PNG/BMP. | Active |
| **[stegoveritas](https://github.com/bannsec/stegoveritas)** | Automatic image steganography analysis. | Active |
| **[OpenStego](https://github.com/syvaidya/openstego)** | Tool to hide/extract data from image. | Active |
| **[imgconceal](https://github.com/tbpaolini/imgconceal)** | Steganography for JPEG/PNG/WebP. | Active |

---

## 🦠 Malware Analysis

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Cuckoo3](https://github.com/cert-ee/cuckoo3)** | Automated malware analysis system. | Active |
| **[YARA](https://github.com/VirusTotal/yara)** | Pattern matching for malware detection. | Active |
| **[CAPEv2](https://github.com/kevoreilly/CAPEv2)** | Malware configuration and payload extraction. | Active |

---

## 🎯 Threat Intelligence

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[MISP](https://github.com/MISP/MISP)** | Threat intelligence platform. | Active |
| **[OpenCTI](https://github.com/OpenCTI-Platform/opencti)** | Open cyber threat intelligence platform. | Active |
| **[YETI](https://github.com/yeti-platform/yeti)** | Your Everyday Threat Intelligence. | Active |
| **[IntelMQ](https://github.com/certtools/intelmq)** | Solution for CERTs processing security data. | Active |

---

## 🔒 VPN/Proxy & Anonymity

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Tor](https://github.com/torproject/tor)** | Anonymity network. | Active |
| **[ProxyChains](https://github.com/haad/proxychains)** | Redirect connections through proxy servers. | Active |

---

## 📊 Log Analysis & SIEM

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Wazuh](https://github.com/wazuh/wazuh)** | Open source security monitoring. | Active |
| **[Elastic Security](https://github.com/elastic/security-docs)** | Security analytics. | Active |
| **[Splunk](https://github.com/splunk)** | Data analysis and visualization. | Active |
| **[Graylog](https://github.com/Graylog2/graylog2-server)** | Log management. | Active |

---

## 📝 Pentest Reporting

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[APTRS](https://github.com/APTRS/APTRS)** | Automated reporting. | Active |
| **[FACTION](https://github.com/factionsecurity/faction)** | OWASP pentesting report generation. | Active |
| **[PeTeReport](https://github.com/1modm/petereport)** | Penetration test report tool. | Active |
| **[WriteHat](https://github.com/blacklanternsecurity/writehat)** | Pentest reporting tool (Markdown → PDF). | Active |

---

## 🤖 AI/ML Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox)** | Adversarial Robustness Toolbox. | Active |
| **[SecML-Torch](https://github.com/pralab/secml-torch)** | Deep learning evaluation. | Active |
| **[TextAttack](https://github.com/QData/TextAttack)** | NLP adversarial attacks. | Active |
| **[Cyber Security ML Toolbox](https://github.com/wszhs/Cyber-Security-ML-Toolbox)** | Adversarial ML for security. | Active |

---

## 🐚 Reverse Shell & Webshell

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Reverse Shell Generator](https://github.com/0dayCTF/reverse-shell-generator)** | Hosted reverse shell generator. | Active |
| **[RevShellGen](https://github.com/t0thkr1s/revshellgen)** | Reverse shell generator with encoding. | Active |
| **[HoaxShell](https://github.com/t3l3machus/hoaxshell)** | Windows reverse shell. | Active |
| **[Webshell-CLI](https://github.com/qtc-de/webshell-cli)** | Command line interface for webshells. | Active |

---

## ⬆️ Privilege Escalation

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[LinPEAS](https://github.com/carlospolop/PEASS-ng)** | Linux privilege escalation awesome script. | Active |
| **[WinPEAS](https://github.com/carlospolop/PEASS-ng)** | Windows privilege escalation awesome script. | Active |
| **[Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)** | Linux enumeration tool. | Active |
| **[Offensive Linux Privilege Escalation](https://github.com/InfoSecWarrior/Offensive-Linux-Privilege-Escalation)** | Linux privesc techniques. | Feb 2025 |

---

## 🔗 Post-Exploitation

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Pupy](https://github.com/n1nj4sec/pupy)** | Cross-platform post-exploitation C2. | May 2025 |
| **[GraphRunner](https://github.com/dafthack/GraphRunner)** | Post-exploitation for MS Graph API. | Active |
| **[GraphSpy](https://github.com/RedByte1337/GraphSpy)** | Initial access and post-exploitation for Office365. | Active |
| **[SharpStrike](https://github.com/iomoath/SharpStrike)** | C# post-exploitation using WMI/CIM. | Active |
| **[Cable](https://github.com/logangoins/Cable)** | .NET toolkit for Active Directory. | Aug 2024 |

---

## 📚 Resources & Wordlists

| Resource | Description | Link |
| :--- | :--- | :--- |
| **[SecLists](https://github.com/danielmiessler/SecLists)** | Collection of lists for security assessments. | GitHub |
| **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** | Useful payloads and bypasses. | GitHub |
| **[FuzzDB](https://github.com/fuzzdb-project/fuzzdb)** | Dictionary of attack patterns. | GitHub |
| **[HackTricks](https://github.com/HackTricks-wiki/hacktricks)** | Wiki-book with hacking tricks. | GitHub |

---


&lt;div align="center"&gt;

&lt;br/&gt;

**LEGAL DISCLAIMER**
&lt;br/&gt;
*This repository is for educational purposes and authorized security research only.*
*Do not use these tools on systems you do not own or have permission to test.*

&lt;/div&gt;
