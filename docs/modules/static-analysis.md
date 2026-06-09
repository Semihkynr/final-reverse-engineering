# Modül 1: Static Analysis

> BGT210 — Reverse Engineering · Istinye University · Semih Kaynar
> Son Güncelleme: 2026-06-10

---

## Tanım

Static analysis, hedef binary veya kaynak kodun **çalıştırılmadan** incelenmesi sürecidir. Execution ortamına ihtiyaç duyulmaz; bu nedenle en güvenli ve ilk uygulanması gereken analiz yöntemidir.

---

## Amaçlar

- Binary'nin dosya formatı, mimarisi ve genel yapısını anlamak
- Import/export table, string ve metadata analizi yapmak
- Obfuscation veya packing mekanizmalarını tespit etmek
- Dynamic analysis için öncelikleri belirlemek

---

## Adım 1 — Dosya Triage

### 1.1 Dosya Türü Tespiti

Binary'nin gerçek türü, uzantısına değil **magic byte**'larına bakılarak belirlenir.

```bash
file suspicious_file
```

| Magic Bytes | Dosya Türü |
|---|---|
| `4D 5A` (MZ) | Windows PE (EXE, DLL) |
| `7F 45 4C 46` (ELF) | Linux/Unix ELF binary |
| `50 4B 03 04` (PK) | ZIP / APK / JAR |
| `25 50 44 46` (%PDF) | PDF |
| `D0 CF 11 E0` | Microsoft OLE (DOC, XLS) |

### 1.2 Hash Hesaplama ve Threat Intelligence

```bash
md5sum suspicious_file
sha256sum suspicious_file
```

Hash değerleri **VirusTotal** ve **MalwareBazaar**'da sorgulanmalıdır. Bilinen bir tehdit ailesiyle eşleşme, analizi hızlandırır.

---

## Adım 2 — Packer / Protector Tespiti

Packed binary'ler analizi zorlaştırır; önce unpack edilmeleri gerekir.

### 2.1 Tespit Yöntemleri

**Entropy analizi:** Normal bir PE dosyasının section entropy'si 5.0–6.5 arasındadır. 7.0'ın üzerindeki değerler sıkıştırma veya şifreleme işaret eder.

**Detect-It-Easy (DiE)** ile otomatik tespit:

```bash
die suspicious.exe
```

### 2.2 Yaygın Packer'lar ve Unpacking

| Packer | Tespit | Unpacking Yöntemi |
|---|---|---|
| UPX | DiE / `upx -t` | `upx -d suspicious.exe` |
| Themida | DiE / section adları | OllyDumpEx + manual |
| MPRESS | DiE | OllyDumpEx |
| Custom XOR | Yüksek entropy + kısa import | x64dbg ile OEP tespiti + dump |

---

## Adım 3 — PE Structure Analizi

### 3.1 PE Header

**PE-bear** veya **CFF Explorer** ile PE header alanları incelenir:

| Alan | Açıklama | Şüpheli Değer |
|---|---|---|
| `TimeDateStamp` | Derleme zamanı | Gelecek tarih veya 0 |
| `Subsystem` | `WINDOWS_GUI` veya `WINDOWS_CUI` | — |
| `NumberOfSections` | Section sayısı | Çok az (1-2) veya çok fazla |
| `SizeOfCode` | Code section boyutu | 0 (packer işareti) |

### 3.2 Section Analizi

```python
import pefile
import math

def calculate_entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return entropy

pe = pefile.PE("suspicious.exe")
for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    entropy = calculate_entropy(section.get_data())
    print(f"{name:10} | Entropy: {entropy:.2f} | Size: {section.SizeOfRawData}")
```

**Şüpheli Section İsimleri:**

| İsim | Anlamı |
|---|---|
| `.packed` | Açıkça packed |
| `UPX0`, `UPX1` | UPX ile packed |
| `.ndata` | NSIS installer |
| Rastgele karakterler | Custom packer |

### 3.3 Import Table Analizi

Import edilen API'ler, binary'nin yapabileceği işlemlerin en önemli göstergesidir.

**Şüpheli API Kategorileri:**

| Kategori | API'ler | Risk |
|---|---|---|
| Process Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | CRITICAL |
| Persistence | `RegSetValueExA`, `SHGetFolderPath` | HIGH |
| Network | `WSAStartup`, `connect`, `send`, `recv`, `InternetOpenA` | HIGH |
| Crypto | `CryptEncrypt`, `CryptGenKey` | MEDIUM |
| Anti-Analysis | `IsDebuggerPresent`, `GetTickCount`, `NtQueryInformationProcess` | HIGH |
| File Operations | `CreateFileA`, `WriteFile`, `DeleteFileA` | MEDIUM |

---

## Adım 4 — String Analizi

### 4.1 Araçlar

```bash
# Standart strings
strings -n 6 suspicious.exe

# Wide strings (UTF-16)
strings -n 6 -e l suspicious.exe

# FLOSS — obfuscated strings dahil
floss suspicious.exe
```

### 4.2 Şüpheli String Kategorileri

| Kategori | Örnek |
|---|---|
| C2 URL/IP | `http://`, `https://`, IP adresi |
| Registry key | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Shell command | `cmd.exe /c`, `powershell -enc` |
| Base64 payload | `/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef...` |
| Mutex adı | Genellikle anlamsız string (anti-duplicate) |
| File path | `%APPDATA%`, `%TEMP%`, `C:\Windows\System32` |

---

## Adım 5 — Disassembly ve Decompilation

### 5.1 Ghidra ile Analiz

1. Ghidra'yı aç → New Project → Import File
2. Auto-analyze: Evet (tüm analyzer'lar aktif)
3. `Symbol Tree` → `Functions` → entry point fonksiyonundan başla
4. `Window` → `Decompiler` ile pseudo-code görüntüle
5. Şüpheli fonksiyonları sağ tık → `References` → nereden çağrıldığına bak

### 5.2 Önemli Fonksiyon Tespiti

Aşağıdaki pattern'leri içeren fonksiyonlar öncelikli incelenmelidir:

- `VirtualAlloc` + `memcpy` + `call register` → shellcode execution
- `CreateProcess` + `WriteProcessMemory` → process hollowing
- `RegSetValueEx` → persistence
- Döngü içinde XOR operasyonu → string deobfuscation

### 5.3 Control Flow Graph

Ghidra'da `Graph` → `Show Function Graph` ile CFG görüntülenebilir. Çok sayıda karşılaştırma + çıkış noktası içeren bloklar anti-debug kontrollerini işaret eder.

---

## Adım 6 — YARA Rule Eşleştirme

```bash
yara -r rules/ suspicious.exe
```

Temel YARA rule örneği:

```yara
rule Suspicious_PE_Injection
{
    meta:
        description = "Detects common process injection API combination"
        author = "Semih Kaynar"
        date = "2026-06-10"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}
```

---

## Static Analysis Checklist

| # | Adım | Araç | Tamamlandı |
|---|---|---|---|
| 1 | Dosya türü tespiti (magic bytes) | `file`, `TrID` | ☐ |
| 2 | Hash hesaplama + VirusTotal | `sha256sum`, VT API | ☐ |
| 3 | Packer / protector tespiti | `DiE`, `PEiD` | ☐ |
| 4 | PE header analizi | `PE-bear`, `CFF Explorer` | ☐ |
| 5 | Section entropy analizi | `pestudio`, `pefile` | ☐ |
| 6 | Import table analizi | `PE-bear`, `pestudio` | ☐ |
| 7 | String extraction (plaintext + wide + FLOSS) | `strings`, `FLOSS` | ☐ |
| 8 | Disassembly ve CFG | `Ghidra` | ☐ |
| 9 | Decompilation | `Ghidra` | ☐ |
| 10 | YARA rule eşleştirme | `yara` | ☐ |
| 11 | Anti-analysis teknik tespiti | Manuel | ☐ |
| 12 | Crypto constant tespiti | `findcrypt` plugin | ☐ |

---

## Çıktılar / Outputs

Bu modülün tamamlanmasıyla üretilen çıktılar:

- `static_report.json` — tüm statik bulgular
- `strings.txt` — extract edilmiş string'ler
- `imports.csv` — import tablosu
- `sections.csv` — section listesi (entropy dahil)
- `yara_matches.txt` — YARA eşleşme sonuçları

---

*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*
