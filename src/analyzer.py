#!/usr/bin/env python3
"""
Reverse Engineering Static Analyzer
BGT210 - Istinye University
Author: Semih Kaynar
"""

import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_hashes(filepath: str) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def detect_file_type(data: bytes) -> str:
    signatures = {
        b"\x4d\x5a": "PE (Windows Executable)",
        b"\x7f\x45\x4c\x46": "ELF (Linux Binary)",
        b"\x50\x4b\x03\x04": "ZIP / APK / JAR",
        b"\x25\x50\x44\x46": "PDF",
        b"\xd0\xcf\x11\xe0": "Microsoft OLE (DOC/XLS)",
        b"\x1f\x8b": "GZIP",
        b"\x42\x5a\x68": "BZIP2",
        b"\x52\x61\x72\x21": "RAR Archive",
    }
    for magic, name in signatures.items():
        if data[:len(magic)] == magic:
            return name
    return "Unknown"


def extract_strings(data: bytes, min_len: int = 6) -> dict:
    ascii_strings = []
    wide_strings = []

    # ASCII strings
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                ascii_strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        ascii_strings.append("".join(current))

    # Wide (UTF-16 LE) strings
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7e and data[i + 1] == 0x00:
            chars = []
            j = i
            while j < len(data) - 1 and 0x20 <= data[j] <= 0x7e and data[j + 1] == 0x00:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= min_len:
                wide_strings.append("".join(chars))
            i = j
        else:
            i += 1

    return {"ascii": list(set(ascii_strings)), "wide": list(set(wide_strings))}


def flag_suspicious_strings(strings_list: list) -> list:
    patterns = [
        "cmd.exe", "powershell", "wscript", "cscript",
        "http://", "https://", "ftp://",
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "WSAStartup", "connect", "send", "recv",
        "CryptEncrypt", "CryptDecrypt",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "base64", "WScript.Shell", "HKEY_",
        ".onion", "token=", "password=", "passwd",
    ]
    flagged = []
    for s in strings_list:
        for p in patterns:
            if p.lower() in s.lower():
                flagged.append({"string": s, "pattern": p})
                break
    return flagged


def analyze_pe(filepath: str) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed. Run: pip install pefile"}

    result = {
        "sections": [],
        "imports": [],
        "exports": [],
        "timestamp": None,
        "architecture": None,
        "is_packed_heuristic": False,
        "suspicious_imports": [],
    }

    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        return {"error": f"PE parse error: {e}"}

    # Architecture
    if pe.FILE_HEADER.Machine == 0x014c:
        result["architecture"] = "x86 (32-bit)"
    elif pe.FILE_HEADER.Machine == 0x8664:
        result["architecture"] = "x86-64 (64-bit)"
    elif pe.FILE_HEADER.Machine == 0xAA64:
        result["architecture"] = "ARM64"

    # Timestamp
    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        result["timestamp"] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError):
        result["timestamp"] = f"Invalid (0x{ts:08x})"

    # Sections
    high_entropy_count = 0
    for section in pe.sections:
        data = section.get_data()
        entropy = calculate_entropy(data)
        name = section.Name.decode(errors="replace").rstrip("\x00")
        sec_info = {
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "size": section.SizeOfRawData,
            "entropy": entropy,
            "flags": hex(section.Characteristics),
        }
        result["sections"].append(sec_info)
        if entropy > 7.0:
            high_entropy_count += 1

    if high_entropy_count > 0:
        result["is_packed_heuristic"] = True

    # Imports
    suspicious_apis = [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "WSAStartup", "connect", "send", "recv", "InternetOpenA", "URLDownloadToFile",
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "ShellExecuteA", "ShellExecuteW", "CreateProcessA",
        "OpenProcess", "TerminateProcess",
    ]

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode(errors="replace")
                    result["imports"].append({"dll": dll_name, "function": func_name})
                    if func_name in suspicious_apis:
                        result["suspicious_imports"].append({
                            "dll": dll_name,
                            "function": func_name,
                        })

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                result["exports"].append(exp.name.decode(errors="replace"))

    return result


def generate_report(filepath: str, output_dir: str = "./reports") -> dict:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print(f"[*] Analyzing: {filepath}")

    with open(filepath, "rb") as f:
        data = f.read()

    file_size = len(data)
    file_type = detect_file_type(data)
    hashes = compute_hashes(filepath)
    overall_entropy = calculate_entropy(data)
    strings_result = extract_strings(data)
    all_strings = strings_result["ascii"] + strings_result["wide"]
    suspicious_strings = flag_suspicious_strings(all_strings)

    report = {
        "meta": {
            "analyzer": "BGT210 RE Framework",
            "author": "Semih Kaynar",
            "university": "Istinye University",
            "analysis_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target_file": os.path.basename(filepath),
            "file_size_bytes": file_size,
        },
        "file_info": {
            "type": file_type,
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "overall_entropy": overall_entropy,
        },
        "strings": {
            "ascii_count": len(strings_result["ascii"]),
            "wide_count": len(strings_result["wide"]),
            "suspicious": suspicious_strings,
        },
        "pe_analysis": {},
        "risk_assessment": {},
    }

    if file_type.startswith("PE"):
        pe_result = analyze_pe(filepath)
        report["pe_analysis"] = pe_result

    # Risk assessment
    risk_score = 0
    risk_factors = []

    if overall_entropy > 7.0:
        risk_score += 30
        risk_factors.append("HIGH: Overall file entropy > 7.0 (possible encryption/packing)")

    if len(suspicious_strings) > 0:
        risk_score += min(len(suspicious_strings) * 5, 30)
        risk_factors.append(f"MEDIUM: {len(suspicious_strings)} suspicious string(s) detected")

    pe = report.get("pe_analysis", {})
    if pe.get("is_packed_heuristic"):
        risk_score += 20
        risk_factors.append("HIGH: Packed binary detected (high entropy section)")

    if len(pe.get("suspicious_imports", [])) > 0:
        count = len(pe["suspicious_imports"])
        risk_score += min(count * 5, 20)
        risk_factors.append(f"HIGH: {count} suspicious API import(s) detected")

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    report["risk_assessment"] = {
        "score": risk_score,
        "level": risk_level,
        "factors": risk_factors,
    }

    # Save JSON report
    base_name = Path(filepath).stem
    json_path = Path(output_dir) / f"{base_name}_static_report.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved: {json_path}")

    # Save Markdown report
    md_path = Path(output_dir) / f"{base_name}_static_report.md"
    _write_markdown_report(report, md_path)
    print(f"[+] Markdown report saved: {md_path}")

    return report


def _write_markdown_report(report: dict, output_path: Path):
    meta = report["meta"]
    fi = report["file_info"]
    risk = report["risk_assessment"]
    pe = report.get("pe_analysis", {})
    strings = report["strings"]

    lines = [
        "# Static Analysis Report",
        "",
        f"> **Analyzer:** {meta['analyzer']}  ",
        f"> **Author:** {meta['author']} — {meta['university']}  ",
        f"> **Date:** {meta['analysis_time']}",
        "",
        "---",
        "",
        "## File Information",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **File Name** | `{meta['target_file']}` |",
        f"| **File Size** | {meta['file_size_bytes']:,} bytes |",
        f"| **File Type** | {fi['type']} |",
        f"| **MD5** | `{fi['md5']}` |",
        f"| **SHA256** | `{fi['sha256']}` |",
        f"| **Overall Entropy** | {fi['overall_entropy']} |",
        "",
        "---",
        "",
        "## Risk Assessment",
        "",
        f"**Risk Level: {risk['level']}** (Score: {risk['score']}/100)",
        "",
        "| Factor |",
        "|---|",
    ]

    for factor in risk["factors"]:
        lines.append(f"| {factor} |")

    lines += [
        "",
        "---",
        "",
        "## PE Analysis",
        "",
    ]

    if "error" in pe:
        lines.append(f"> {pe['error']}")
    else:
        lines += [
            f"| Field | Value |",
            f"|---|---|",
            f"| **Architecture** | {pe.get('architecture', 'N/A')} |",
            f"| **Compile Timestamp** | {pe.get('timestamp', 'N/A')} |",
            f"| **Packed (heuristic)** | {'YES ⚠️' if pe.get('is_packed_heuristic') else 'No'} |",
            "",
            "### Sections",
            "",
            "| Name | Virtual Address | Size | Entropy |",
            "|---|---|---|---|",
        ]
        for sec in pe.get("sections", []):
            flag = " ⚠️" if sec["entropy"] > 7.0 else ""
            lines.append(f"| `{sec['name']}` | {sec['virtual_address']} | {sec['size']} | {sec['entropy']}{flag} |")

        lines += [
            "",
            "### Suspicious Imports",
            "",
            "| DLL | Function |",
            "|---|---|",
        ]
        for imp in pe.get("suspicious_imports", []):
            lines.append(f"| `{imp['dll']}` | `{imp['function']}` |")
        if not pe.get("suspicious_imports"):
            lines.append("| — | No suspicious imports detected |")

    lines += [
        "",
        "---",
        "",
        "## String Analysis",
        "",
        f"- ASCII strings extracted: **{strings['ascii_count']}**",
        f"- Wide strings extracted: **{strings['wide_count']}**",
        f"- Suspicious strings flagged: **{len(strings['suspicious'])}**",
        "",
        "### Suspicious Strings",
        "",
        "| String | Matched Pattern |",
        "|---|---|",
    ]
    for s in strings["suspicious"][:50]:
        lines.append(f"| `{s['string'][:80]}` | `{s['pattern']}` |")
    if not strings["suspicious"]:
        lines.append("| — | No suspicious strings detected |")

    lines += [
        "",
        "---",
        "",
        "*BGT210 — Reverse Engineering · Istinye University · Spring 2025-2026*",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="BGT210 RE Framework — Static Binary Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python analyzer.py --file suspicious.exe --output reports/",
    )
    parser.add_argument("--file", required=True, help="Target binary file path")
    parser.add_argument("--output", default="./reports", help="Output directory for reports")
    parser.add_argument("--strings-only", action="store_true", help="Only extract strings")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON (no Markdown)")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    if args.strings_only:
        with open(args.file, "rb") as f:
            data = f.read()
        result = extract_strings(data)
        print(f"[*] ASCII strings ({len(result['ascii'])}):")
        for s in result["ascii"]:
            print(f"    {s}")
        print(f"\n[*] Wide strings ({len(result['wide'])}):")
        for s in result["wide"]:
            print(f"    {s}")
        return

    report = generate_report(args.file, args.output)

    print("\n" + "=" * 60)
    print(f"  RISK LEVEL : {report['risk_assessment']['level']}")
    print(f"  RISK SCORE : {report['risk_assessment']['score']}/100")
    print("=" * 60)
    for factor in report["risk_assessment"]["factors"]:
        print(f"  • {factor}")
    print("=" * 60)


if __name__ == "__main__":
    main()
