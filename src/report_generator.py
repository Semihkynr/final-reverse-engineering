#!/usr/bin/env python3
"""
Report Generator — converts JSON analysis data into Markdown reports
BGT210 - Istinye University | Semih Kaynar
"""

import json
import sys
from datetime import datetime
from pathlib import Path


MITRE_MAPPING = {
    "VirtualAllocEx": ("T1055.001", "Process Injection: Dynamic-link Library Injection"),
    "WriteProcessMemory": ("T1055.001", "Process Injection"),
    "CreateRemoteThread": ("T1055.001", "Process Injection"),
    "IsDebuggerPresent": ("T1622", "Debugger Evasion"),
    "CheckRemoteDebuggerPresent": ("T1622", "Debugger Evasion"),
    "RegSetValueExA": ("T1547.001", "Boot or Logon Autostart: Registry Run Keys"),
    "RegSetValueExW": ("T1547.001", "Boot or Logon Autostart: Registry Run Keys"),
    "URLDownloadToFile": ("T1105", "Ingress Tool Transfer"),
    "InternetOpenA": ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "WSAStartup": ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "CryptEncrypt": ("T1027", "Obfuscated Files or Information"),
    "CryptDecrypt": ("T1140", "Deobfuscate/Decode Files or Information"),
    "ShellExecuteA": ("T1059", "Command and Scripting Interpreter"),
    "CreateProcessA": ("T1059", "Command and Scripting Interpreter"),
}


def load_json_report(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def map_to_mitre(suspicious_imports: list) -> list:
    seen = set()
    techniques = []
    for imp in suspicious_imports:
        func = imp.get("function", "")
        if func in MITRE_MAPPING and func not in seen:
            seen.add(func)
            tid, tname = MITRE_MAPPING[func]
            techniques.append({
                "technique_id": tid,
                "technique_name": tname,
                "evidence": f"`{func}` import detected",
            })
    return techniques


def generate_full_report(json_path: str, output_dir: str = "./reports") -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    data = load_json_report(json_path)

    meta = data.get("meta", {})
    fi = data.get("file_info", {})
    risk = data.get("risk_assessment", {})
    pe = data.get("pe_analysis", {})
    strings = data.get("strings", {})

    suspicious_imports = pe.get("suspicious_imports", [])
    mitre_techniques = map_to_mitre(suspicious_imports)

    lines = [
        "# Reverse Engineering Analysis Report",
        "",
        "> **Classification:** TLP:AMBER — İlgili ekipler dışında paylaşılamaz",
        f"> **Report Date:** {meta.get('analysis_time', datetime.utcnow().isoformat())}",
        f"> **Analyst:** {meta.get('author', 'N/A')} — {meta.get('university', 'N/A')}",
        f"> **Analyzer:** {meta.get('analyzer', 'N/A')}",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"| Alan | Değer |",
        f"|---|---|",
        f"| **Analiz Konusu** | `{meta.get('target_file', 'N/A')}` |",
        f"| **Tehdit Seviyesi** | **{risk.get('level', 'N/A')}** |",
        f"| **Risk Skoru** | {risk.get('score', 0)}/100 |",
        f"| **Dosya Türü** | {fi.get('type', 'N/A')} |",
        f"| **Mimari** | {pe.get('architecture', 'N/A')} |",
        f"| **Packed** | {'Evet ⚠️' if pe.get('is_packed_heuristic') else 'Hayır'} |",
        "",
    ]

    if risk.get("factors"):
        lines += ["**Kritik Bulgular:**", ""]
        for f_item in risk["factors"]:
            lines.append(f"- {f_item}")
        lines.append("")

    lines += [
        "---",
        "",
        "## 2. Sample Metadata",
        "",
        "| Özellik | Değer |",
        "|---|---|",
        f"| **Dosya Adı** | `{meta.get('target_file', 'N/A')}` |",
        f"| **MD5** | `{fi.get('md5', 'N/A')}` |",
        f"| **SHA256** | `{fi.get('sha256', 'N/A')}` |",
        f"| **Dosya Boyutu** | {meta.get('file_size_bytes', 0):,} bytes |",
        f"| **Dosya Türü** | {fi.get('type', 'N/A')} |",
        f"| **Overall Entropy** | {fi.get('overall_entropy', 'N/A')} |",
        f"| **Derleme Tarihi** | {pe.get('timestamp', 'N/A')} |",
        f"| **Packed (Heuristic)** | {'Evet' if pe.get('is_packed_heuristic') else 'Hayır'} |",
        "",
        "---",
        "",
        "## 3. Static Analysis Findings",
        "",
        "### 3.1 PE Sections",
        "",
        "| Section | Sanal Adres | Boyut | Entropy | Durum |",
        "|---|---|---|---|---|",
    ]

    for sec in pe.get("sections", []):
        status = "⚠️ Yüksek Entropy" if sec.get("entropy", 0) > 7.0 else "Normal"
        lines.append(
            f"| `{sec['name']}` | {sec.get('virtual_address', 'N/A')} | "
            f"{sec.get('size', 0):,} | {sec.get('entropy', 0)} | {status} |"
        )

    lines += [
        "",
        "### 3.2 Suspicious Imports",
        "",
        "| DLL | Function | Risk |",
        "|---|---|---|",
    ]
    for imp in suspicious_imports:
        lines.append(f"| `{imp['dll']}` | `{imp['function']}` | HIGH |")
    if not suspicious_imports:
        lines.append("| — | Şüpheli import tespit edilmedi | — |")

    lines += [
        "",
        "### 3.3 Suspicious Strings",
        "",
        f"Toplam şüpheli string: **{len(strings.get('suspicious', []))}**",
        "",
        "| String | Kategori |",
        "|---|---|",
    ]
    for s in strings.get("suspicious", [])[:30]:
        lines.append(f"| `{s['string'][:80]}` | `{s['pattern']}` |")

    lines += [
        "",
        "---",
        "",
        "## 4. MITRE ATT&CK Mapping",
        "",
        "| Technique ID | Technique Name | Kanıt |",
        "|---|---|---|",
    ]
    for t in mitre_techniques:
        lines.append(f"| [{t['technique_id']}](https://attack.mitre.org/techniques/{t['technique_id'].replace('.', '/')}) | {t['technique_name']} | {t['evidence']} |")
    if not mitre_techniques:
        lines.append("| — | Eşleşme bulunamadı | — |")

    lines += [
        "",
        "---",
        "",
        "## 5. Risk Assessment",
        "",
        f"**Risk Level: {risk.get('level', 'N/A')}** | Score: {risk.get('score', 0)}/100",
        "",
        "| Risk Faktörü |",
        "|---|",
    ]
    for factor in risk.get("factors", []):
        lines.append(f"| {factor} |")

    lines += [
        "",
        "---",
        "",
        "## 6. Recommendations / Öneriler",
        "",
        "| Öncelik | Öneri |",
        "|---|---|",
        "| **HIGH** | Dynamic analysis ile davranış doğrulaması yapılmalı |",
        "| **HIGH** | Hash değerleri EDR/SIEM sistemlerine IOC olarak eklenmeli |",
        "| **MEDIUM** | Tespit edilen şüpheli import'lar için memory forensics uygulanmalı |",
        "| **MEDIUM** | Network monitoring fazına geçilerek C2 iletişimi araştırılmalı |",
        "| **LOW** | Kaynak binary arşivlenmeli ve hash'i dokümante edilmeli |",
        "",
        "---",
        "",
        "*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*",
        f"*Rapor oluşturma tarihi: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*",
    ]

    base_name = Path(json_path).stem.replace("_static_report", "")
    out_path = Path(output_dir) / f"{base_name}_full_report.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Full report saved: {out_path}")
    return str(out_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <json_report> [output_dir]")
        sys.exit(1)

    json_file = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "./reports"
    generate_full_report(json_file, out_dir)
