# References / Kaynaklar

> BGT210 — Reverse Engineering · Istinye University · Semih Kaynar
> Son Güncelleme: 2026-06-10

---

## Kitaplar / Books

| # | Başlık | Yazar(lar) | Yayınevi | Yıl | Konu |
|---|---|---|---|---|---|
| 1 | *Practical Malware Analysis* | Sikorski, M. & Honig, A. | No Starch Press | 2012 | Malware analizi temeli — temel referans |
| 2 | *The IDA Pro Book* (2nd Ed.) | Eagle, C. | No Starch Press | 2011 | IDA Pro kullanımı ve RE metodolojisi |
| 3 | *Reversing: Secrets of Reverse Engineering* | Eilam, E. | Wiley | 2005 | RE teorisi ve binary analiz |
| 4 | *The Art of Memory Forensics* | Ligh, M. et al. | Wiley | 2014 | Memory dump analizi, Volatility |
| 5 | *Malware Analyst's Cookbook* | Ligh, M. et al. | Wiley | 2010 | Pratik analiz tarifleri ve araç kullanımı |
| 6 | *Hacking: The Art of Exploitation* | Erickson, J. | No Starch Press | 2008 | Exploit geliştirme ve binary düzeyi güvenlik |
| 7 | *Windows Internals* (7th Ed.) | Russinovich, M. et al. | Microsoft Press | 2017 | Windows OS mimarisi — dynamic analysis için temel |

---

## Akademik Makaleler / Academic Papers

| # | Başlık | Kaynak | Yıl | Link |
|---|---|---|---|---|
| 1 | *Automated Malware Analysis via Android Emulation* | IEEE S&P | 2012 | — |
| 2 | *A Survey of Techniques for Internet Traffic Classification using Deep Learning* | IEEE Comm. Surveys | 2019 | — |
| 3 | *Obfuscation-Resilient Executable Payload Extraction from Packed Malware* | USENIX Security | 2021 | — |
| 4 | *FLOSS: FLARE Obfuscated String Solver* | FireEye / Mandiant | 2016 | https://github.com/mandiant/flare-floss |

---

## Standartlar ve Framework'ler / Standards & Frameworks

| # | Standart | Organizasyon | Açıklama | URL |
|---|---|---|---|---|
| 1 | MITRE ATT&CK | MITRE Corporation | Saldırı taktik ve tekniklerinin sınıflandırması | https://attack.mitre.org |
| 2 | NIST SP 800-86 | NIST | Adli bilişim tekniklerinin IR'a entegrasyonu | https://csrc.nist.gov/publications/detail/sp/800-86/final |
| 3 | NIST SP 800-61 Rev. 2 | NIST | Bilgisayar güvenliği olay yönetimi rehberi | https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final |
| 4 | CVSS v3.1 | FIRST | Ortak güvenlik açığı puanlama sistemi | https://www.first.org/cvss/v3.1/specification-document |
| 5 | OpenIOC | Mandiant | Tehdit göstergesi tanım standardı | https://openioc.org |
| 6 | STIX / TAXII | OASIS | Tehdit istihbaratı paylaşım formatı | https://oasis-open.github.io/cti-documentation/ |

---

## Araçlar / Tools

### Disassembler / Decompiler

| Araç | Lisans | URL | Notlar |
|---|---|---|---|
| **Ghidra** | Ücretsiz (NSA) | https://ghidra-sre.org | Bu projede kullanıldı |
| **IDA Pro** | Ticari | https://hex-rays.com/ida-pro | Endüstri standardı |
| **Binary Ninja** | Ticari/Community | https://binary.ninja | Modern API |
| **Cutter (Rizin)** | Ücretsiz | https://cutter.re | Açık kaynak alternatif |
| **RetDec** | Ücretsiz | https://github.com/avast/retdec | Avast tarafından geliştirilen decompiler |

### Debugger

| Araç | Platform | URL | Notlar |
|---|---|---|---|
| **x64dbg** | Windows | https://x64dbg.com | Bu projede kullanıldı |
| **WinDbg Preview** | Windows | https://apps.microsoft.com/store/detail/windbg/9PGJGD53TN86 | Kernel debug |
| **GDB + pwndbg** | Linux | https://github.com/pwndbg/pwndbg | CTF / Linux analizi |
| **Frida** | Cross-platform | https://frida.re | Dynamic instrumentation |

### PE / Binary Analizi

| Araç | URL | Notlar |
|---|---|---|
| **PE-bear** | https://github.com/hasherezade/pe-bear | Detaylı PE görselleştirme |
| **pestudio** | https://www.winitor.com | Hızlı triage |
| **CFF Explorer** | https://ntcore.com/?page_id=388 | Import/Export analizi |
| **Detect-It-Easy (DiE)** | https://github.com/horsicq/Detect-It-Easy | Packer/compiler tespiti |
| **FLOSS** | https://github.com/mandiant/flare-floss | Obfuscated string çözme |

### Network Analizi

| Araç | URL | Notlar |
|---|---|---|
| **Wireshark** | https://www.wireshark.org | Bu projede kullanıldı |
| **mitmproxy** | https://mitmproxy.org | HTTP/HTTPS MITM |
| **Zeek (Bro)** | https://zeek.org | Network traffic analizi |
| **NetworkMiner** | https://www.netresec.com/?page=NetworkMiner | PCAP analizi |
| **INetSim** | https://www.inetsim.org | Sahte internet servisleri |
| **REMnux** | https://remnux.org | Malware analiz Linux distro'su |

### Sandbox / Otomatik Analiz

| Platform | URL | Notlar |
|---|---|---|
| **CAPE Sandbox** | https://capesandbox.com | Bu projede kullanıldı (self-hosted) |
| **Any.run** | https://any.run | Cloud sandbox |
| **Cuckoo 3** | https://cuckoosandbox.org | Self-hosted sandbox |
| **VirusTotal** | https://www.virustotal.com | Hash/file lookup |
| **MalwareBazaar** | https://bazaar.abuse.ch | Malware sample DB |

### Python Kütüphaneleri

| Kütüphane | PyPI | Kullanım |
|---|---|---|
| `pefile` | https://pypi.org/project/pefile/ | PE format parse |
| `lief` | https://pypi.org/project/lief/ | Multi-format binary parse |
| `capstone` | https://pypi.org/project/capstone/ | Disassembly engine |
| `yara-python` | https://pypi.org/project/yara-python/ | YARA rule matching |
| `rich` | https://pypi.org/project/rich/ | Terminal output formatting |
| `jinja2` | https://pypi.org/project/Jinja2/ | Rapor template engine |

---

## Online Kaynaklar / Online Resources

| Kaynak | URL | Açıklama |
|---|---|---|
| MalAPI.io | https://malapi.io | Windows API → malicious use mapping |
| VirusTotal Graph | https://www.virustotal.com/graph | IOC ilişki haritası |
| OALabs | https://oalabs.openanalysis.net | RE tutorial ve writeup |
| Malware Traffic Analysis | https://www.malware-traffic-analysis.net | PCAP örnekleri |
| ANY.RUN Blog | https://any.run/cybersecurity-blog | Malware analiz writeup |
| FLARE Team Blog | https://www.mandiant.com/resources/blog | Mandiant RE araştırmaları |
| Hex-Rays Blog | https://hex-rays.com/blog | IDA Pro ve RE teknikleri |
| Ghidra Docs | https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html | Resmi Ghidra rehberi |

---

## CTF / Pratik Platform

| Platform | URL | Açıklama |
|---|---|---|
| crackmes.one | https://crackmes.one | RE egzersizleri |
| picoCTF | https://picoctf.org | Başlangıç seviye CTF |
| HackTheBox | https://www.hackthebox.com | Orta-ileri seviye RE |
| reversing.kr | https://reversing.kr | RE odaklı CTF |
| pwn.college | https://pwn.college | Binary exploitation + RE |

---

*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*
