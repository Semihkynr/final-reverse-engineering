# Modül 2: Dynamic Analysis

> BGT210 — Reverse Engineering · Istinye University · Semih Kaynar
> Son Güncelleme: 2026-06-10

---

## Tanım

Dynamic analysis, hedef binary'nin **kontrollü bir ortamda çalıştırılarak** davranışlarının gerçek zamanlı gözlemlenmesi sürecidir. Static analysis'te görülemeyen runtime davranışları (şifre çözme, network bağlantısı, process injection) bu fazda ortaya çıkar.

> **Güvenlik Kuralı:** Dynamic analysis her zaman izole edilmiş bir sandbox veya snapshot alınmış sanal makinede gerçekleştirilmelidir. Host sistemle doğrudan bağlantı kesinlikle kurulmamalıdır.

---

## Ortam Gereksinimleri

### Minimum Gereksinimler

| Bileşen | Gereksinim |
|---|---|
| Hypervisor | VirtualBox 7.x veya VMware Workstation |
| Guest OS | Windows 10 x64 (temiz kurulum) |
| Network | Host-only adapter (internet erişimi yok) |
| Snapshot | Analiz öncesi temiz snapshot zorunlu |
| Disk Alanı | Minimum 50 GB (snapshot + capture için) |

### Önerilen Ortam

**FlareVM** (Windows tabanlı RE distro) üzerinde analiz:

```powershell
# FlareVM kurulumu
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1'))
```

**REMnux** (Linux tabanlı, ağ servisleri için):

REMnux, INetSim ile sahte internet servisleri sunar. Host-only ağda FlareVM'nin gateway'i olarak konumlandırılır.

---

## Adım 1 — Ortam Hazırlığı

### 1.1 Snapshot Al

Analiz başlamadan **önce** temiz snapshot alınması zorunludur:

```
VMware: VM → Snapshot → Take Snapshot → "Clean_baseline"
VirtualBox: Machine → Take Snapshot → "Clean_baseline"
```

### 1.2 Monitoring Araçlarını Başlat

Aşağıdaki araçlar binary çalıştırılmadan **önce** başlatılmalıdır:

```
1. Process Monitor (ProcMon)    → Tüm filter'ları temizle → Capture başlat
2. Process Hacker               → Çalıştır (passif izleme)
3. Wireshark                    → Host-only adapter → Capture başlat
4. RegShot                      → "1st shot" al
```

### 1.3 Network Hazırlığı

```bash
# REMnux üzerinde INetSim başlat
sudo inetsim

# FakeDNS (tüm DNS sorgularını 192.168.x.x'e yönlendir)
sudo fakedns
```

---

## Adım 2 — İlk Çalıştırma (Automated Triage)

Binary ilk olarak minimum müdahaleyle çalıştırılır; temel davranış profili çıkarılır.

```bash
# CAPE Sandbox ile otomatik analiz
curl -X POST "http://localhost:8000/api/tasks/create/file/" \
     -F "file=@suspicious.exe" \
     -F "options=procmemdump=1"
```

Otomatik analiz sonuçları:
- Process tree
- File system değişiklikleri
- Registry değişiklikleri
- Network aktivitesi
- Dropped files

---

## Adım 3 — Process Monitoring

### 3.1 ProcMon Filter Ayarları

Process Monitor'da şu filter'lar uygulanır:

| Filter | Operation | Value |
|---|---|---|
| Process Name | is | `suspicious.exe` |
| Operation | contains | `WriteFile` |
| Operation | contains | `RegSetValue` |
| Operation | contains | `Process Create` |
| Path | contains | `AppData` |

### 3.2 Analiz Edilecek Aktiviteler

**Dosya Sistemi:**

```
CreateFile    → Hangi dosyalar oluşturuluyor?
WriteFile     → İçerik ne?
DeleteFile    → Hangi dosyalar siliniyor? (self-cleanup)
SetFileAttributes → Gizli dosya mı yapılıyor?
```

**Registry:**

```
RegSetValue   → Hangi key'ler yazılıyor?
RegCreateKey  → Yeni key oluşturuluyor mu?
HKCU\...\Run  → Persistence mi?
```

**Process:**

```
Process Create → Yeni process başlatıldı mı?
Thread Create  → Remote thread injection?
```

---

## Adım 4 — Debugger ile Derinlemesine Analiz

### 4.1 x64dbg Temel Kullanımı

```
1. File → Open → suspicious.exe
2. İlk breakpoint: Entry Point (otomatik)
3. Run → F9 (entry point'e kadar çalıştır)
```

### 4.2 Breakpoint Stratejisi

Öncelikli breakpoint noktaları:

| API | Neden? |
|---|---|
| `IsDebuggerPresent` | Anti-debug bypass için |
| `VirtualAlloc` | Shellcode/payload bellek tahsisi |
| `WriteProcessMemory` | Process injection |
| `CreateRemoteThread` | Remote code execution |
| `WSAConnect` / `connect` | C2 bağlantısı |
| `CryptDecrypt` | Şifreli payload çözme |
| `RegSetValueExA` | Persistence kurulumu |

x64dbg'de breakpoint ekleme:

```
Ctrl+G → API adı yaz → Enter → F2 (breakpoint toggle)
```

### 4.3 Anti-Debug Bypass

**ScyllaHide Plugin** (x64dbg için):

```
Plugins → ScyllaHide → Options → Enable all → Apply
```

Manuel patch yöntemi:

```
IsDebuggerPresent çağrısı sonrası:
  TEST EAX, EAX
  JNZ exit_branch    ← Bu jump'ı NOP ile patch
```

### 4.4 Memory Dump

Unpack edilmiş payload'u hafızadan dump alma:

```
Process Hacker → Suspicious Process → sağ tık → Properties
→ Memory → Yüksek entropi bölge → Dump
```

veya x64dbg ile:

```
Memory Map → Sağ tık → Dump to File
```

---

## Adım 5 — API Monitoring

### 5.1 API Monitor Kullanımı

```
API Monitor → Monitor New Process → suspicious.exe
→ Filter: kernel32.dll, ws2_32.dll, advapi32.dll
→ Start Monitoring
```

### 5.2 Frida ile Dynamic Instrumentation

```javascript
// inject.js — tüm network bağlantılarını logla
const connect = Module.findExportByName('ws2_32.dll', 'connect');
Interceptor.attach(connect, {
    onEnter(args) {
        const sockaddr = args[1];
        const port = sockaddr.add(2).readU16();
        const ip = sockaddr.add(4).readU32();
        console.log(`[connect] IP: ${ip} Port: ${port}`);
    }
});
```

```bash
frida -l inject.js -f suspicious.exe --no-pause
```

---

## Adım 6 — Behavior Timeline Oluşturma

Tüm gözlemler kronolojik sıraya dizilir:

| Zaman | Eylem | Araç | Detay |
|---|---|---|---|
| T+0s | Process başlatıldı | ProcMon | PID: XXXX |
| T+0.1s | Anti-debug kontrolü | x64dbg | `IsDebuggerPresent` → false döndü |
| T+0.5s | Memory allocation | x64dbg | `VirtualAlloc` → 0x1000 byte |
| T+1s | Payload decode | x64dbg | XOR loop tamamlandı |
| T+2s | Yeni process | ProcMon | `cmd.exe /c whoami` |
| T+3s | Registry write | ProcMon | HKCU\...\Run |
| T+5s | Network bağlantısı | Wireshark | TCP SYN → 185.x.x.x:443 |

---

## Dynamic Analysis Checklist

| # | Adım | Araç | Tamamlandı |
|---|---|---|---|
| 1 | Temiz snapshot alındı | VMware / VirtualBox | ☐ |
| 2 | ProcMon başlatıldı | Process Monitor | ☐ |
| 3 | Wireshark capture başlatıldı | Wireshark | ☐ |
| 4 | RegShot 1st shot alındı | RegShot | ☐ |
| 5 | INetSim başlatıldı (REMnux) | INetSim | ☐ |
| 6 | Binary çalıştırıldı | — | ☐ |
| 7 | File system aktivitesi loglandı | ProcMon | ☐ |
| 8 | Registry değişiklikleri loglandı | RegShot 2nd shot | ☐ |
| 9 | Process tree incelendi | Process Hacker | ☐ |
| 10 | Debugger breakpoint'leri işlendi | x64dbg | ☐ |
| 11 | Anti-debug bypass uygulandı | ScyllaHide | ☐ |
| 12 | Memory dump alındı | Process Hacker | ☐ |
| 13 | API call log incelendi | API Monitor | ☐ |
| 14 | Behavior timeline hazırlandı | Manuel | ☐ |
| 15 | Snapshot'a dönüldü (cleanup) | VMware / VirtualBox | ☐ |

---

## Çıktılar / Outputs

| Dosya | İçerik |
|---|---|
| `procmon_log.pml` | Tam ProcMon kaydı |
| `regshot_diff.txt` | Registry değişiklik farkı |
| `memory_dump.dmp` | Process memory dump |
| `api_calls.log` | API call log |
| `behavior_timeline.md` | Kronolojik eylem listesi |
| `dynamic_report.json` | Yapılandırılmış bulgular |

---

*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*
