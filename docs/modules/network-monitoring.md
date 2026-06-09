# Modül 3: Network Monitoring

> BGT210 — Reverse Engineering · Istinye University · Semih Kaynar
> Son Güncelleme: 2026-06-10

---

## Tanım

Network monitoring fazında, analiz edilen binary'nin ürettiği **network traffic** yakalanır, decode edilir ve analiz edilir. Bu faz; C2 (Command & Control) iletişimi, data exfiltration, DNS tünelleme ve custom protocol tespiti için kritik öneme sahiptir.

---

## Ortam Mimarisi

```
┌─────────────────────────────┐
│   FlareVM (Analysis VM)     │
│   Windows 10 x64            │
│   IP: 172.20.0.10           │
│   Gateway: 172.20.0.2       │
└──────────────┬──────────────┘
               │ Host-Only Network
               │ (172.20.0.0/24)
┌──────────────▼──────────────┐
│   REMnux (Gateway VM)        │
│   Ubuntu + INetSim           │
│   IP: 172.20.0.2            │
│                              │
│  ┌─────────────────────┐    │
│  │ INetSim Services     │    │
│  │ • FakeDNS (UDP 53)  │    │
│  │ • FakeHTTP (80/443) │    │
│  │ • FakeSMTP (25)     │    │
│  │ • FakeFTP (21)      │    │
│  └─────────────────────┘    │
│                              │
│  Wireshark / tcpdump         │
└─────────────────────────────┘
         │ (İzole — İnternete çıkış YOK)
```

---

## Adım 1 — Ortam Hazırlığı

### 1.1 REMnux Üzerinde INetSim Yapılandırması

```bash
# /etc/inetsim/inetsim.conf
service_bind_address  172.20.0.2
dns_default_ip        172.20.0.2
dns_default_hostname  malware-c2.local
http_bind_port        80
https_bind_port       443

# INetSim başlatma
sudo inetsim
```

### 1.2 Wireshark Capture Başlatma

```bash
# REMnux üzerinde (veya host-only interface üzerinde)
wireshark -i eth0 -w capture.pcap &

# tcpdump alternatifi
tcpdump -i eth0 -w capture.pcap -s 0
```

### 1.3 FakeDNS Yapılandırması

Tüm DNS sorgularının loglanması için:

```bash
# fakedns başlatma (tüm sorguları 172.20.0.2'ye yönlendir)
sudo fakedns -i eth0 2>&1 | tee dns_queries.log
```

---

## Adım 2 — Packet Capture ve Temel Analiz

### 2.1 Wireshark Display Filters

| Amaç | Filter |
|---|---|
| DNS sorgularını görüntüle | `dns` |
| HTTP traffic | `http` |
| Belirli IP | `ip.addr == 185.x.x.x` |
| Belirli port | `tcp.port == 4444` |
| HTTP POST istekleri | `http.request.method == "POST"` |
| TCP SYN (bağlantı girişimleri) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| DNS TXT kayıtları (tünelleme) | `dns.qry.type == 16` |
| Büyük payload'lar | `frame.len > 1000` |

### 2.2 İlk 5 Dakika Analizi

Binary başlatıldıktan sonra izlenecek sıra:

1. **DNS sorguları** — Hangi domain'ler sorgulandı?
2. **TCP bağlantı girişimleri** — Hangi IP:port'lara?
3. **HTTP/HTTPS trafik** — Hangi URL'ler çağrıldı?
4. **Veri miktarı** — Dışarıya ne kadar veri gönderildi?
5. **Timing / interval** — Düzenli aralıklı mı? (beaconing)

---

## Adım 3 — DNS Analizi

### 3.1 DNS Query Tespiti

```bash
# PCAP'tan DNS sorgularını çıkar
tshark -r capture.pcap -Y "dns.flags.response == 0" \
       -T fields -e frame.time -e dns.qry.name | sort -u
```

### 3.2 DGA (Domain Generation Algorithm) Tespiti

DGA kullanan malware, rastgele görünen domain'ler üretir:

| Normal Domain | DGA Domain |
|---|---|
| `google.com` | `xkq7r2mnvp.ru` |
| `microsoft.com` | `a9b3f1kz.cn` |
| `github.com` | `m2nx7pqr9s.biz` |

**Tespit yöntemi:** Sorguların entropisini hesapla, leksik analiz yap.

### 3.3 DNS Tunneling Tespiti

```bash
# Olağandışı uzun DNS sorgularını bul
tshark -r capture.pcap -Y "dns" \
       -T fields -e dns.qry.name | awk 'length > 50'
```

DNS tünelleme işaretleri:
- Çok uzun subdomain'ler (50+ karakter)
- Base64/Hex benzeri subdomain içeriği
- Yüksek DNS sorgu frekansı
- TXT record sorguları

---

## Adım 4 — HTTP/HTTPS Analizi

### 4.1 HTTP Traffic İnceleme

```bash
# HTTP isteklerini listele
tshark -r capture.pcap -Y "http.request" \
       -T fields -e http.request.method -e http.request.uri \
       -e http.host -e http.user_agent

# HTTP POST body'lerini çıkar
tshark -r capture.pcap -Y "http.request.method == POST" \
       -T fields -e http.request.uri -e http.file_data
```

**Şüpheli HTTP Pattern'ler:**

| Pattern | Anlamı |
|---|---|
| `User-Agent: Mozilla/4.0` (eski) | Hardcoded UA — bot işareti |
| Base64 encoded body | Obfuscated veri |
| Düzenli aralıklı POST | Beaconing |
| PUT `/gate.php` | Klasik C2 endpoint |
| Cookie'de base64 | Gizli veri exfiltration |

### 4.2 HTTPS Traffic Analizi

TLS şifreli trafikte içerik görülmez, ancak şunlar analiz edilebilir:

**TLS Certificate:**

```bash
# Sertifika bilgilerini çıkar
tshark -r capture.pcap -Y "tls.handshake.type == 11" \
       -T fields -e tls.handshake.certificate
```

**JA3 Fingerprint** (TLS client fingerprint):

```bash
# ja3 ile fingerprint
ja3 capture.pcap
```

**SSL Stripping (mitmproxy):**

```bash
# mitmproxy ile TLS intercept
mitmproxy --mode transparent --ssl-insecure
```

---

## Adım 5 — C2 Communication Pattern Analizi

### 5.1 Beaconing Tespiti

Düzenli aralıklı giden paketler C2 beaconing'i işaret eder:

```bash
# Zeek ile beaconing analizi
zeek -r capture.pcap local
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration
```

**Beaconing Kriterleri:**

| Özellik | Normal | Şüpheli |
|---|---|---|
| İstek aralığı | Düzensiz | Sabit ± birkaç saniye |
| İstek boyutu | Değişken | Sabit veya çok küçük |
| Hedef | Bilinen CDN | Bilinmeyen IP |
| Süre | Kısa | Saatler/günler |

### 5.2 Data Exfiltration Tespiti

```bash
# Dışarıya giden büyük veri transferleri
tshark -r capture.pcap -Y "ip.dst != 172.20.0.0/24" \
       -T fields -e ip.dst -e frame.len | \
       awk '{sum[$1]+=$2} END {for(ip in sum) print sum[ip], ip}' | \
       sort -rn | head -20
```

---

## Adım 6 — IOC Extraction

### 6.1 Otomatik IOC Çıkarma

```bash
# NetworkMiner ile otomatik extraction
NetworkMiner.exe -r capture.pcap

# strings + grep ile PCAP'tan IOC çıkarma
strings capture.pcap | grep -E \
    "(https?://[^\s]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
```

### 6.2 IOC Kategorileri

| Kategori | Format | Örnek |
|---|---|---|
| IP Address | IPv4/IPv6 | `185.220.101.x` |
| Domain | FQDN | `update-service.ru` |
| URL | Full URL | `https://x.ru/gate.php` |
| JA3 Hash | MD5 | `51c64c77e60f3980eea90869b68c58a8` |
| User-Agent | String | `Mozilla/4.0 (compatible)` |

### 6.3 MITRE ATT&CK Network Mapping

| Teknik ID | Teknik Adı | Gözlem |
|---|---|---|
| T1071.001 | Web Protocols | HTTPS beaconing |
| T1071.004 | DNS | DNS TXT exfiltration |
| T1041 | Exfiltration Over C2 | POST ile veri gönderimi |
| T1568.002 | DGA | Rastgele domain sorguları |
| T1573.001 | Symmetric Cryptography | Encrypted payload |

---

## Network Monitoring Checklist

| # | Adım | Araç | Tamamlandı |
|---|---|---|---|
| 1 | INetSim başlatıldı (REMnux) | INetSim | ☐ |
| 2 | Wireshark capture başlatıldı | Wireshark | ☐ |
| 3 | FakeDNS başlatıldı | FakeDNS | ☐ |
| 4 | DNS sorguları loglandı | Wireshark / tshark | ☐ |
| 5 | HTTP/HTTPS trafik analiz edildi | Wireshark | ☐ |
| 6 | TLS certificate incelendi | Wireshark | ☐ |
| 7 | Beaconing pattern analizi yapıldı | Zeek / Rita | ☐ |
| 8 | Data exfiltration kontrol edildi | tshark | ☐ |
| 9 | DNS tunneling kontrol edildi | tshark | ☐ |
| 10 | IOC'ler çıkarıldı (IP, domain, URL) | NetworkMiner | ☐ |
| 11 | MITRE ATT&CK teknikleri eşleştirildi | Manuel | ☐ |
| 12 | PCAP arşivlendi | Wireshark | ☐ |

---

## Çıktılar / Outputs

| Dosya | İçerik |
|---|---|
| `capture.pcap` | Tam network capture |
| `dns_queries.log` | DNS sorgu log'u |
| `http_requests.log` | HTTP istek listesi |
| `ioc_list.yaml` | IP, domain, URL IOC'leri |
| `network_report.json` | Yapılandırılmış ağ bulguları |
| `mitre_network.md` | ATT&CK mapping |

---

*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*
