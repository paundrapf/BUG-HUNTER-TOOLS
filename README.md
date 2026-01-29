<div align="center">

![Terminal Glitch](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdW12anZ4anZ4anZ4anZ4anZ4anZ4anZ4anZ4/26xBI73gWquCBBCDe/giphy.gif)

# MODERN HACKING TOOLS (FOR BUG HUNTER) 2025-2026

**Curated. Verified. Lethal.**
*The complete collection of active hacking tools for the modern era.*

[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Maintenance](https://img.shields.io/badge/maintained-YES-00ff00?style=flat-square)](https://github.com/yourusername/repo)
[![Tools](https://img.shields.io/badge/count-200%2B-ff00ff?style=flat-square)](https://github.com/yourusername/repo)

</div>

---

## ⚡ Criteria
We don't do "abandonware". Everything here is:
1.  **Active:** Last commit 2024-2026.
2.  **Functional:** No critical bugs ignored for >6 months.
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
*   [VPN & Anonymity](#-vpnproxy--anonymity)
*   [Log Analysis](#-log-analysis--siem)
*   [Reporting](#-pentest-reporting)
*   [AI/ML Security](#-aiml-security)
*   [Shells](#-reverse-shell--webshell)
*   [Privilege Escalation](#-privilege-escalation)
*   [Post-Exploitation](#-post-exploitation)

---

## 🌐 Web Application Security

### Scanners & Injection
| Tool | Description | Status |
| :--- | :--- | :--- |
| **[DalFox](https://github.com/hahwul/dalfox)** | XSS scanner & parameter analyzer (Go). | Active |
| **[FinDOM-XSS](https://github.com/dwisiswant0/findom-xss)** | Fast DOM-based XSS finder. | Active |
| **[SQLMap](https://github.com/sqlmapproject/sqlmap)** | Automatic SQL injection tool. | 2025 |
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
| **[CloudBrute](https://github.com/0xsha/CloudBrute)** | Cloud infrastructure enumeration. | Active |
| **[Pacu](https://github.com/RhinoSecurityLabs/pacu)** | AWS exploitation framework. | Active |
| **[PMapper](https://github.com/nccgroup/PMapper)** | AWS IAM privilege escalation. | Active |
| **[S3Scanner](https://github.com/sa7mon/S3Scanner)** | S3 bucket discovery. | Active |

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
| **[Shodan](https://github.com/achillean/shodan-python)** | IoT search engine library. | Active |
| **[Sherlock](https://github.com/sherlock-project/sherlock)** | Social media account hunter. | Active |
| **[Holehe](https://github.com/megadose/holehe)** | Email to social media checker. | Active |

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
| **[Responder](https://github.com/lgandx/Responder)** | LLMNR/NBT-NS poisoner. | Active |
| **[Kerbrute](https://github.com/ropnop/kerbrute)** | Kerberos bruteforce. | Active |
| **[Rubeus](https://github.com/GhostPack/Rubeus)** | Raw Kerberos interaction. | Active |
| **[Certipy](https://github.com/ly4k/Certipy)** | AD CS abuse tool. | Active |
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

---

## 📟 IoT Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Binwalk](https://github.com/ReFirmLabs/binwalk)** | Firmware extractor. | Oct 2024 |
| **[FACT_core](https://github.com/fkie-cad/FACT_core)** | Firmware comparison tool. | Active |
| **[Firmadyne](https://github.com/attify/firmware-analysis-toolkit)** | Firmware emulation. | Active |
| **[EMBA](https://github.com/e-m-b-a/emba)** | Security analyzer. | Active |
| **[Unblob](https://github.com/onekey-sec/unblob)** | Modern extraction suite. | Active |
| **[PENIOT](https://github.com/yakuza8/peniot)** | IoT penetration tester. | Active |

---

## 📡 Wireless Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)** | WiFi auditing suite. | Active |
| **[WiFi Scanner](https://github.com/RaheesAhmed/wifi_scanner)** | Rust-based scanner. | Apr 2025 |
| **[Blue-sec](https://github.com/irfan-sec/Blue-sec)** | Bluetooth hacking. | Nov 2025 |
| **[Bluescan](https://github.com/DasSecurity-HatLab/bluescan)** | Bluetooth scanner. | Active |
| **[Proxmark3](https://github.com/RfidResearchGroup/proxmark3)** | RFID analysis tool. | Sep 2025 |
| **[HackRF](https://github.com/greatscottgadgets/hackrf)** | SDR peripheral. | Active |

---

## 🚗 Automotive Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[can-utils](https://github.com/linux-can/can-utils)** | Linux CAN utilities. | Active |
| **[SavvyCAN](https://github.com/collin80/SavvyCAN)** | CAN bus analysis. | May 2025 |
| **[CaringCaribou](https://github.com/CaringCaribou/caringcaribou)** | Friendly car hacking tool. | Aug 2024 |
| **[ICSim](https://github.com/zombieCraig/ICSim)** | Instrument Cluster Sim. | Active |
| **[Carpunk](https://github.com/souravbaghz/Carpunk)** | CAN Injection Toolkit. | Active |

---

## 🔧 Hardware Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Bus Pirate](https://github.com/BusPirate/Bus_Pirate)** | Universal serial interface. | Active |
| **[HydraBus](https://github.com/hydrabus/hydrabus)** | Multi-tool hardware. | Active |
| **[ChipWhisperer](https://github.com/newaetech/chipwhisperer)** | Side-channel attacks. | Active |
| **[JTAGULATOR](https://github.com/grandideastudio/jtagulator)** | JTAG pinout detector. | Active |

---

## 🎯 Red Team C2 Frameworks

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Sliver](https://github.com/BishopFox/sliver)** | Adversary emulation. | Active |
| **[Havoc](https://github.com/HavocFramework/Havoc)** | Modern post-exploit C2. | Active |
| **[Mythic](https://github.com/its-a-feature/Mythic)** | Multi-platform C2. | Active |
| **[Covenant](https://github.com/cobbr/Covenant)** | .NET C2 framework. | Active |

---

## 🔍 Digital Forensics

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Volatility3](https://github.com/volatilityfoundation/volatility3)** | Memory forensics. | Active |
| **[Autopsy](https://github.com/sleuthkit/autopsy)** | Digital forensics platform. | Active |
| **[TheHive](https://github.com/TheHive-Project/TheHive)** | Incident response platform. | Jul 2025 |
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
| **[Stegseek](https://github.com/RickdeJager/stegseek)** | Steghide cracker. | Active |
| **[zsteg](https://github.com/zed-0xff/zsteg)** | Detect hidden data (PNG/BMP). | Active |

---

## 🦠 Malware Analysis & Threat Intel

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Cuckoo3](https://github.com/cert-ee/cuckoo3)** | Automated analysis. | Active |
| **[YARA](https://github.com/VirusTotal/yara)** | Pattern matching. | Active |
| **[MISP](https://github.com/MISP/MISP)** | Threat sharing platform. | Active |
| **[OpenCTI](https://github.com/OpenCTI-Platform/opencti)** | Threat intel platform. | Active |

---

## 🔒 VPN, Proxy & SIEM

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[Tor](https://github.com/torproject/tor)** | Anonymity network. | Active |
| **[ProxyChains](https://github.com/haad/proxychains)** | Proxy redirector. | Active |
| **[Wazuh](https://github.com/wazuh/wazuh)** | Security monitoring. | Active |
| **[Elastic](https://github.com/elastic/security-docs)** | Security analytics. | Active |

---

## 📝 Reporting & Documentation

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[APTRS](https://github.com/APTRS/APTRS)** | Automated reporting. | Active |
| **[PeTeReport](https://github.com/1modm/petereport)** | Penetration test report. | Active |

---

## 🤖 AI/ML Security

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox)** | Adversarial Robustness Toolbox. | Active |
| **[SecML-Torch](https://github.com/pralab/secml-torch)** | Deep learning evaluation. | Active |
| **[TextAttack](https://github.com/QData/TextAttack)** | NLP adversarial attacks. | Active |

---

## 🐚 Shells & Post-Exploitation

| Tool | Description | Status |
| :--- | :--- | :--- |
| **[RevShellGen](https://github.com/t0thkr1s/revshellgen)** | Shell generator. | Active |
| **[HoaxShell](https://github.com/t3l3machus/hoaxshell)** | Windows reverse shell. | Active |
| **[LinPEAS](https://github.com/carlospolop/PEASS-ng)** | Linux privesc script. | Active |
| **[WinPEAS](https://github.com/carlospolop/PEASS-ng)** | Windows privesc script. | Active |
| **[Pupy](https://github.com/n1nj4sec/pupy)** | Cross-platform C2. | May 2025 |
| **[GraphRunner](https://github.com/dafthack/GraphRunner)** | MS Graph API post-exploit. | Active |

---

<div align="center">

<br/>

**LEGAL DISCLAIMER**
<br/>
*This repository is for educational purposes and authorized security research only.*
*Do not use these tools on systems you do not own or have permission to test.*

</div>
