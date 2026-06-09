#!/usr/bin/env python3
"""
String Extractor — ASCII, Wide, and encoded string extraction
BGT210 - Istinye University | Semih Kaynar
"""

import base64
import re
import sys
from pathlib import Path


SUSPICIOUS_PATTERNS = [
    (r"https?://[^\s\"'<>]+", "URL"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IPv4 Address"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Possible Base64"),
    (r"(?:cmd|powershell|wscript|cscript)(?:\.exe)?", "Shell Command"),
    (r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Persistence Registry Key"),
    (r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)", "Registry Hive"),
    (r"%(?:APPDATA|TEMP|SYSTEMROOT|WINDIR|USERPROFILE)%", "Environment Variable Path"),
    (r"(?:password|passwd|credentials?|secret|apikey|api_key)\s*[=:]\s*\S+", "Credential Pattern"),
    (r"(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread)", "Injection API"),
    (r"(?:IsDebuggerPresent|CheckRemoteDebuggerPresent)", "Anti-Debug API"),
]


def extract_ascii(data: bytes, min_len: int = 6) -> list:
    result = []
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return list(dict.fromkeys(result))


def extract_wide(data: bytes, min_len: int = 6) -> list:
    result = []
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7e and data[i + 1] == 0x00:
            chars = []
            j = i
            while j < len(data) - 1 and 0x20 <= data[j] <= 0x7e and data[j + 1] == 0x00:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= min_len:
                result.append("".join(chars))
            i = j
        else:
            i += 1
    return list(dict.fromkeys(result))


def try_decode_base64(s: str) -> str | None:
    try:
        decoded = base64.b64decode(s + "==")
        if all(0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d) for b in decoded):
            return decoded.decode("ascii")
    except Exception:
        pass
    return None


def flag_suspicious(strings: list) -> list:
    flagged = []
    for s in strings:
        for pattern, label in SUSPICIOUS_PATTERNS:
            match = re.search(pattern, s, re.IGNORECASE)
            if match:
                entry = {
                    "string": s,
                    "match": match.group(0),
                    "category": label,
                }
                # Try to decode if it looks like base64
                if label == "Possible Base64":
                    decoded = try_decode_base64(match.group(0))
                    if decoded:
                        entry["decoded"] = decoded
                flagged.append(entry)
                break
    return flagged


def extract_all(filepath: str, min_len: int = 6) -> dict:
    data = Path(filepath).read_bytes()
    ascii_strings = extract_ascii(data, min_len)
    wide_strings = extract_wide(data, min_len)
    all_strings = ascii_strings + wide_strings
    suspicious = flag_suspicious(all_strings)

    return {
        "ascii": ascii_strings,
        "wide": wide_strings,
        "suspicious": suspicious,
        "stats": {
            "ascii_count": len(ascii_strings),
            "wide_count": len(wide_strings),
            "suspicious_count": len(suspicious),
        },
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python string_extractor.py <file> [min_length]")
        sys.exit(1)

    filepath = sys.argv[1]
    min_len = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    result = extract_all(filepath, min_len)

    print(f"[*] ASCII strings: {result['stats']['ascii_count']}")
    print(f"[*] Wide strings:  {result['stats']['wide_count']}")
    print(f"[*] Suspicious:    {result['stats']['suspicious_count']}")
    print()

    if result["suspicious"]:
        print("[!] SUSPICIOUS STRINGS:")
        print("-" * 60)
        for s in result["suspicious"]:
            print(f"  [{s['category']}] {s['string'][:100]}")
            if "decoded" in s:
                print(f"    → Decoded: {s['decoded'][:80]}")
