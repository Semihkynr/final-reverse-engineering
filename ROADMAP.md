# ROADMAP — Reverse Engineering Methodology & Analysis Framework

> **Course:** BGT210 — Reverse Engineering · Istinye University
> **Instructor:** Keyvan Arasteh
> **Student:** Semih Kaynar (`2420****1011`)
> **Semester:** 2025-2026 Spring

---

> *"Understand first, then code. Think like a detective: observe, translate raw data, identify patterns, report findings."*

---

## Phase 0 — Understand Before You Build / Yazmadan Önce Anla

Bu fazda herhangi bir kod yazmadan önce projenin temel sorularına cevap aradım.

| Soru | Cevap |
|---|---|
| Proje nedir? | Binary dosyaları ve zararlı yazılımları analiz eden sistematik bir RE framework'ü |
| Nasıl çalışır? | Static → Dynamic → Network → Report pipeline'ı |
| Girdiler nelerdir? | PE (Windows EXE/DLL), ELF (Linux binary), şüpheli dosyalar |
| Çıktılar nelerdir? | Structured Markdown raporu, IOC listesi, MITRE ATT&CK mapping |
| Hangi araçlar kullanılacak? | Python (`pefile`, `capstone`, `lief`), Ghidra, x64dbg, Wireshark |
| Neden bu araçlar? | Açık kaynak, scriptable, endüstri standardı |

### Temel Kavramların Anlaşılması

- **Static Analysis:** Binary çalıştırılmadan yapılan inceleme. PE header, import table, string analizi.
- **Dynamic Analysis:** Kontrollü ortamda çalıştırarak davranış gözlemleme. API call logging, memory dump.
- **Network Monitoring:** Oluşturulan network traffic'in yakalanması. Packet sniffing, C2 tespiti.
- **Disassembler:** Machine code → Assembly dönüşümü yapan araç (Ghidra, IDA Pro).
- **Debugger:** Binary'nin adım adım çalıştırılmasını sağlayan araç (x64dbg, WinDbg).

---

## Phase 1 — Research & Investigation / Araştırma ve Keşif

> Tüm araştırma notları: `docs/research/`

### 1.1 Metodoloji Araştırması

| Konu | Durum | Notlar |
|---|---|---|
| RE metodolojisi standartları (NIST, OWASP) | ✅ Tamamlandı | `docs/research/reverse-engineering-methodology.md` |
| MITRE ATT&CK framework incelemesi | ✅ Tamamlandı | Tactic/Technique mapping eklendi |
| PE format spesifikasyonu | ✅ Tamamlandı | Microsoft PE/COFF spec, `pefile` kütüphanesi |
| Packing ve obfuscation teknikleri | ✅ Tamamlandı | UPX, Themida, custom XOR |
| Anti-debug / Anti-VM teknikleri | ✅ Tamamlandı | IsDebuggerPresent, CPUID, timing checks |
| C2 communication patterns | ✅ Tamamlandı | Beaconing, DNS tunneling, HTTPS C2 |

### 1.2 Tool Araştırması

| Araç | Karar | Gerekçe |
|---|---|---|
| IDA Pro vs Ghidra | **Ghidra** seçildi | Ücretsiz, scriptable, NSA kalitesinde decompiler |
| x64dbg vs OllyDbg | **x64dbg** seçildi | Aktif geliştirme, 64-bit destek, plugin ekosistemi |
| Wireshark vs tcpdump | **Wireshark** seçildi | GUI + filter + protocol dissector |
| CAPE vs Cuckoo | **CAPE** seçildi | Daha modern codebase, aktif topluluk |
| `pefile` vs `lief` | **İkisi birden** | `pefile` detaylı PE analizi, `lief` cross-format |

### 1.3 Çıkmaz Sokaklar (Dead Ends)

> Başarısız denemeler ve öğrenilenler:

- **Radare2 scripting:** r2pipe API'sinin dokümantasyonu yetersiz bulundu; Ghidra Python API'sine geçildi.
- **Automated unpacking:** UPX dışındaki packerlar için otomasyonun güvenilir olmadığı görüldü; manuel approach benimsendi.
- **Windows Sandbox API:** Microsoft Sandbox API'si bazı malware davranışlarını tetiklemiyor; VMware snapshot tercih edildi.

---

## Phase 2 — Environment Setup / Ortam Kurulumu

### 2.1 Analiz Ortamı

- [x] Docker container yapılandırması (`Dockerfile`, `docker-compose.yml`)
- [x] Python 3.11 sanal ortam ve bağımlılıklar (`requirements.txt`)
- [x] `.env.example` şablonu oluşturuldu
- [x] Isolated network (host-only) konfigürasyonu dokümante edildi

### 2.2 Tool Kurulumu (VM / Host)

- [x] Ghidra 11.x kurulumu ve temel script'ler
- [x] x64dbg + ScyllaHide plugin
- [x] Wireshark + INetSim (REMnux)
- [x] CAPE Sandbox (self-hosted Docker)
- [x] Python kütüphaneleri: `pefile`, `capstone`, `lief`, `yara-python`

### 2.3 Güvenlik Kontrolleri

- [x] Snapshot alındı (analiz VM)
- [x] Network izolasyonu test edildi
- [x] Host ↔ VM clipboard/dragdrop devre dışı bırakıldı

---

## Phase 3 — Implementation / Uygulama

### Modül 1: Static Analyzer (`src/analyzer.py`)

1. `pefile` ile PE header parse → dosya türü, mimari, timestamp
2. Section analizi → entropy hesaplama, şüpheli section tespiti
3. Import table analizi → şüpheli API pattern matching
4. String extraction → plaintext + wide string + encoded string
5. Hash hesaplama → MD5, SHA256, imphash
6. YARA rule entegrasyonu → known malware family tespiti
7. Packer detection → PE karakteristiklerine göre heuristic
8. JSON çıktı formatı → rapor üreticiye veri aktarımı

### Modül 2: Report Generator (`src/report_generator.py`)

1. JSON analiz verisini al
2. Jinja2 template engine ile Markdown rapor üret
3. MITRE ATT&CK mapping ekle (API call → technique)
4. IOC listesi çıkar (IP, domain, hash, file path)
5. Risk skoru hesapla (CVSS benzeri heuristic)
6. Raporu `reports/` klasörüne kaydet

### Modül 3: Metodoloji Dokümanı (`docs/research/`)

1. Static Analysis faz dokümantasyonu
2. Dynamic Analysis faz dokümantasyonu
3. Network Monitoring faz dokümantasyonu
4. Mermaid decision flowchart
5. Mermaid process flowchart
6. Tool comparison matrix
7. Professional report template
8. MITRE ATT&CK mapping tablosu

---

## Phase 4 — Testing & Reporting / Test ve Raporlama

### 4.1 Test Senaryoları

| Senaryo | Dosya | Beklenen Sonuç | Durum |
|---|---|---|---|
| Temiz PE binary | `notepad.exe` | Şüpheli bulgu yok | ✅ |
| UPX packed binary | `upx_sample.exe` | Packer tespiti | ✅ |
| Şüpheli import | `inject_sample.exe` | `WriteProcessMemory` uyarısı | ✅ |
| Yüksek entropi section | `encrypted_payload.exe` | Şifreli içerik uyarısı | ✅ |

### 4.2 Raporlama

- [x] Her analiz fazı için bulgular Markdown formatında belgelendi
- [x] IOC'ler YAML formatında dışa aktarıldı
- [x] MITRE ATT&CK teknikleri haritalandı
- [x] Metodoloji dokümanı peer review sürecinden geçirildi

---

## Phase 5 — Delivery Checklist / Teslim Kontrol Listesi

### Repo Yapısı

- [x] `README.md` — tüm zorunlu bölümler mevcut
- [x] `ROADMAP.md` — tüm fazlar doldurulmuş
- [x] `Dockerfile` — çalışır durumda
- [x] `docker-compose.yml` — multi-container yapılandırma
- [x] `.env.example` — gerçek değer içermiyor
- [x] `.gitignore` — `.env`, `venv/`, `*.pyc`, binary'ler hariç tutulmuş
- [x] `docs/modules/` — her modül için ayrı `.md` dosyası
- [x] `docs/research/` — metodoloji dokümanı ve araştırma notları
- [x] `docs/references/` — kaynaklar ve araç linkleri
- [x] `src/` — çalışan kaynak kod

### GitHub

- [x] Repo oluşturuldu: `github.com/semihkynr/reverse-engineering-framework`
- [x] Commit mesajları açıklayıcı ve küçük parçalar halinde
- [x] `keyvanarasteh` collaborator olarak eklendi (Read access)
- [ ] Son deadline kontrolü yapıldı

### Kalite

- [x] Tüm Markdown dosyaları düzgün formatlanmış
- [x] Kod içinde gereksiz yorum yok
- [x] Güvenlik açığı içermeyen Python kodu
- [x] `requirements.txt` güncel ve pin'li versiyonlar

---

## Öğrendiklerim / What I Learned

**En zorlu kısım:** Anti-debug bypass tekniklerinin doğru dokümante edilmesi — her tekniğin neden işe yaradığını anlamak, sadece listelemekten çok daha değerliydi.

**En çok şaşırdığım şey:** Ghidra'nın decompiler kalitesinin IDA Pro'ya bu kadar yakın olması. Ücretsiz olmasına rağmen kurumsal analizlerde rahatlıkla kullanılabilir.

**Metodoloji konusunda:** RE'nin doğrusal bir süreç olmadığını, sürekli önceki fazlara geri dönerek iteratif çalışıldığını anladım. Bu yüzden karar flowchart'ı çift yönlü ok içeriyor.

**Araç seçimi konusunda:** "En iyi araç" diye bir şey yok — her araç belirli bir senaryoda üstün. Tool comparison matrix tam da bu yüzden gerekli.

---

*Son Güncelleme: 2026-06-10 | Semih Kaynar | BGT210*
