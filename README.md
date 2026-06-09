<div align="center">
  <a href="https://istinye.edu.tr">
    <img src="docs/assets/istinye-university-logo.webp" alt="Istinye University" width="180"/>
  </a>

  # Reverse Engineering Methodology & Analysis Framework

  ![GitHub](https://img.shields.io/badge/GitHub-semihkynr-red?style=flat-square&logo=github)
  ![Language](https://img.shields.io/badge/Language-Python-blue?style=flat-square&logo=python)
  ![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=flat-square)
  ![Course](https://img.shields.io/badge/Course-BGT210-purple?style=flat-square)
  ![License](https://img.shields.io/badge/License-Educational-green?style=flat-square)
</div>

---

## Instructor / Danışman

| | |
|---|---|
| **Name** | Keyvan Arasteh |
| **GitHub** | [@keyvanarasteh](https://github.com/keyvanarasteh) |
| **Email** | [keyvan.arasteh@istinye.edu.tr](mailto:keyvan.arasteh@istinye.edu.tr) |
| **LinkedIn** | [keyvanarasteh](https://www.linkedin.com/in/keyvanarasteh/) |
| **Website** | [qline.tech](https://qline.tech) |

---

## Student / Öğrenci

| | |
|---|---|
| **Name / Ad Soyad** | Semih Kaynar |
| **Student ID / Öğrenci No** | `2420****1011` |
| **GitHub** | [@semihkynr](https://github.com/semihkynr) |

---

## Course Information / Ders Bilgileri

| | |
|---|---|
| **Course Name** | Reverse Engineering / Tersine Mühendislik |
| **Course Code** | BGT210 |
| **Credits** | 3 ECTS |
| **Prerequisites** | Assembly Language, Operating Systems, Network Fundamentals, Linux CLI |
| **Semester** | 2025-2026 Spring |
| **Institution** | [Istinye University](https://istinye.edu.tr) |

---

## Project Overview / Proje Özeti

Bu proje, binary dosyaların ve şüpheli yazılımların sistematik olarak analiz edilmesi için kurumsal düzeyde bir **Reverse Engineering** metodoloji çerçevesi ve analiz araç seti sunar.

Proje üç ana bileşenden oluşmaktadır:

1. **Metodoloji Dokümanı** — Static Analysis → Dynamic Analysis → Network Monitoring → Reporting aşamalarını kapsayan adım adım rehber (`docs/research/reverse-engineering-methodology.md`)
2. **Analiz Scripti** — PE/ELF binary dosyalarını otomatik olarak analiz eden Python aracı (`src/analyzer.py`)
3. **Raporlama Şablonu** — Kurumsal standartta Markdown tabanlı bulgu raporu şablonu (`docs/modules/`)

---

## Repository Structure / Repo Yapısı

```
reverse-engineering-framework/
├── README.md                          # Ana dokümantasyon
├── ROADMAP.md                         # Öğrenme ve araştırma yolculuğu
├── .env.example                       # Ortam değişkenleri şablonu
├── .gitignore                         # Git dışlama kuralları
├── Dockerfile                         # Container tanımı
├── docker-compose.yml                 # Çok-konteyner düzenlemesi
├── docs/
│   ├── assets/                        # Logo ve görseller
│   ├── modules/
│   │   ├── static-analysis.md        # Static analysis modül dökümantasyonu
│   │   ├── dynamic-analysis.md       # Dynamic analysis modül dökümantasyonu
│   │   └── network-monitoring.md     # Network monitoring modül dökümantasyonu
│   ├── research/
│   │   ├── reverse-engineering-methodology.md  # Ana metodoloji dokümanı
│   │   └── research-notes-template.md          # Araştırma notları şablonu
│   └── references/
│       └── references.md             # Kaynaklar ve araç linkleri
└── src/
    ├── analyzer.py                    # Ana analiz scripti
    ├── pe_parser.py                   # PE format parser
    ├── string_extractor.py            # String extraction modülü
    └── report_generator.py            # Markdown rapor üretici
```

---

## Getting Started / Kurulum

### Gereksinimler

- Docker Engine 24.x+
- Docker Compose 2.x+
- Python 3.11+ (Docker olmadan çalıştırmak için)

### Docker ile Kurulum (Önerilen)

```bash
git clone https://github.com/semihkynr/reverse-engineering-framework
cd reverse-engineering-framework
cp .env.example .env
# .env dosyasını kendi değerlerinizle düzenleyin
docker-compose up -d
```

### Yerel Kurulum

```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
python src/analyzer.py --help
```

### Kullanım Örneği

```bash
# Tek bir binary dosyasını analiz et
python src/analyzer.py --file samples/suspicious.exe --output reports/

# Tüm modülleri çalıştır (static + string extraction + rapor)
python src/analyzer.py --file samples/suspicious.exe --all --output reports/

# Yalnızca string extraction
python src/analyzer.py --file samples/suspicious.exe --strings-only
```

---

## Deliverables / Teslimler

| Bileşen | Durum |
|---|---|
| Metodoloji Dokümanı (`docs/research/`) | ✅ Tamamlandı |
| Static Analysis Modülü | ✅ Tamamlandı |
| Dynamic Analysis Modülü Dökümantasyonu | ✅ Tamamlandı |
| Network Monitoring Modülü Dökümantasyonu | ✅ Tamamlandı |
| Python Analiz Scripti (`src/`) | ✅ Tamamlandı |
| Raporlama Şablonu | ✅ Tamamlandı |
| Docker Ortamı | ✅ Tamamlandı |
| Kaynaklar ve Referanslar | ✅ Tamamlandı |

---

## Documentation / Belgeleme

| Doküman | Konum | Açıklama |
|---|---|---|
| Metodoloji Rehberi | [`docs/research/reverse-engineering-methodology.md`](./docs/research/reverse-engineering-methodology.md) | Tam RE metodolojisi, flowchart'lar, checklist'ler |
| Static Analysis | [`docs/modules/static-analysis.md`](./docs/modules/static-analysis.md) | Disassembly, decompilation, PE analizi |
| Dynamic Analysis | [`docs/modules/dynamic-analysis.md`](./docs/modules/dynamic-analysis.md) | Debugger kullanımı, sandbox, behavior analizi |
| Network Monitoring | [`docs/modules/network-monitoring.md`](./docs/modules/network-monitoring.md) | Packet capture, C2 analizi, IOC extraction |
| Kaynaklar | [`docs/references/references.md`](./docs/references/references.md) | Kitaplar, araçlar, standartlar |

---

## Key Methodology / Temel Metodoloji

```
┌─────────────────┐    ┌──────────────────┐    ┌───────────────────┐    ┌──────────┐
│ Static Analysis │───▶│ Dynamic Analysis │───▶│ Network Monitoring│───▶│Reporting │
│                 │    │                  │    │                   │    │          │
│ • Disassembly   │    │ • Debugger       │    │ • Packet Sniffing │    │ • IOC    │
│ • Decompilation │    │ • API Monitoring │    │ • C2 Detection    │    │ • MITRE  │
│ • String Extrac.│    │ • Memory Dump    │    │ • Traffic Decode  │    │ • CVSS   │
└─────────────────┘    └──────────────────┘    └───────────────────┘    └──────────┘
```

Detaylı metodoloji, karar flowchart'ları ve faz bazlı checklist'ler için:
→ [`docs/research/reverse-engineering-methodology.md`](./docs/research/reverse-engineering-methodology.md)

---

## Tools Used / Kullanılan Araçlar

| Kategori | Araçlar |
|---|---|
| Disassembler / Decompiler | Ghidra, IDA Pro (Free), Binary Ninja |
| Debugger | x64dbg, WinDbg, GDB+pwndbg |
| Network Analysis | Wireshark, mitmproxy, Zeek |
| Sandbox | CAPE Sandbox, Any.run |
| String Extraction | FLOSS, strings |
| PE Analysis | PE-bear, pestudio, CFF Explorer |
| Python Libraries | `pefile`, `capstone`, `lief`, `yara-python` |

---

## References / Kaynaklar

Tüm kaynaklar için → [`docs/references/references.md`](./docs/references/references.md)

Temel kaynaklar:
- Sikorski & Honig — *Practical Malware Analysis* (No Starch Press)
- MITRE ATT&CK Framework — https://attack.mitre.org
- NIST SP 800-86 — Guide to Integrating Forensic Techniques into IR

---

> **Collaborator Note:** Bu repo'ya `keyvanarasteh` collaborator olarak eklenmiştir (Read access).

---

*Istinye University — BGT210 Reverse Engineering · Spring 2025-2026*
