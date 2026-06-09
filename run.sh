#!/usr/bin/env bash
# ============================================================
# run.sh — BGT210 RE Framework Demo Script
# Istinye University | Semih Kaynar
#
# Kullanım:
#   chmod +x run.sh
#   ./run.sh              # Demo modu (test binary oluşturur)
#   ./run.sh <dosya>      # Gerçek binary analizi
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORTS_DIR="./reports"
SAMPLES_DIR="./samples"
DEMO_BINARY="${SAMPLES_DIR}/demo_sample.bin"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   BGT210 — Reverse Engineering Analysis Framework        ║"
    echo "║   Istinye University  |  Semih Kaynar                    ║"
    echo "║   Static Binary Analyzer v1.0                            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_python() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[ERROR] python3 bulunamadı. Lütfen Python 3.9+ kurun.${NC}"
        exit 1
    fi
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo -e "${GREEN}[✓] Python ${PYTHON_VERSION} bulundu${NC}"
}

VENV_DIR=".venv"

setup_venv() {
    if [ ! -d "${VENV_DIR}" ]; then
        echo -e "${BOLD}[*] Virtual environment oluşturuluyor...${NC}"
        python3 -m venv "${VENV_DIR}"
        echo -e "${GREEN}[✓] venv oluşturuldu: ${VENV_DIR}${NC}"
    fi
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    echo -e "${GREEN}[✓] venv aktif${NC}"
}

check_dependencies() {
    echo -e "\n${BOLD}[*] Bağımlılıklar kontrol ediliyor...${NC}"

    setup_venv

    MISSING=0
    for pkg in pefile; do
        if python3 -c "import ${pkg}" 2>/dev/null; then
            echo -e "${GREEN}[✓] ${pkg}${NC}"
        else
            echo -e "${YELLOW}[!] ${pkg} bulunamadı${NC}"
            MISSING=$((MISSING + 1))
        fi
    done

    if [ "$MISSING" -gt 0 ]; then
        echo -e "\n${YELLOW}[*] Eksik bağımlılıklar venv içine kuruluyor...${NC}"
        pip install --quiet -r src/requirements.txt && \
            echo -e "${GREEN}[✓] Bağımlılıklar kuruldu${NC}" || \
            echo -e "${YELLOW}[!] Kurulum başarısız — temel analiz modunda devam ediliyor${NC}"
    fi
}

create_demo_binary() {
    mkdir -p "${SAMPLES_DIR}"
    echo -e "\n${BOLD}[*] Demo test binary'si oluşturuluyor...${NC}"

    python3 - <<'PYEOF'
import struct, os

# Minimal PE binary (MZ + PE header stub) — sadece analiz demosuu için
# Gerçek zararlı kod içermez.

pe_bytes = bytearray()

# MZ Header
pe_bytes += b'MZ'                          # Magic
pe_bytes += b'\x90\x00'                    # Bytes on last page
pe_bytes += b'\x03\x00'                    # Pages in file
pe_bytes += b'\x00\x00'                    # Relocations
pe_bytes += b'\x04\x00'                    # Header size (paragraphs)
pe_bytes += b'\x00\x00'                    # Min extra paragraphs
pe_bytes += b'\xFF\xFF'                    # Max extra paragraphs
pe_bytes += b'\x00\x00'                    # Initial SS
pe_bytes += b'\xB8\x00'                    # Initial SP
pe_bytes += b'\x00\x00'                    # Checksum
pe_bytes += b'\x00\x00'                    # Initial IP
pe_bytes += b'\x00\x00'                    # Initial CS
pe_bytes += b'\x40\x00'                    # Offset to relocation table
pe_bytes += b'\x00\x00'                    # Overlay number
pe_bytes += b'\x00' * 8                    # Reserved
pe_bytes += b'\x00\x00'                    # OEM identifier
pe_bytes += b'\x00\x00'                    # OEM info
pe_bytes += b'\x00' * 20                   # Reserved
pe_bytes += struct.pack('<I', 0x80)        # e_lfanew → PE header at 0x80

# Pad to 0x80
pe_bytes += b'\x00' * (0x80 - len(pe_bytes))

# PE Signature
pe_bytes += b'PE\x00\x00'

# COFF File Header
pe_bytes += struct.pack('<H', 0x8664)      # Machine: x86-64
pe_bytes += struct.pack('<H', 1)           # NumberOfSections: 1
pe_bytes += struct.pack('<I', 0x5F000000)  # TimeDateStamp
pe_bytes += struct.pack('<I', 0)           # PointerToSymbolTable
pe_bytes += struct.pack('<I', 0)           # NumberOfSymbols
pe_bytes += struct.pack('<H', 0xF0)        # SizeOfOptionalHeader
pe_bytes += struct.pack('<H', 0x0002)      # Characteristics: executable

# Optional Header (PE32+)
pe_bytes += struct.pack('<H', 0x020B)      # Magic: PE32+
pe_bytes += b'\x0E\x00'                    # Linker version
pe_bytes += struct.pack('<I', 0x200)       # SizeOfCode
pe_bytes += struct.pack('<I', 0)           # SizeOfInitializedData
pe_bytes += struct.pack('<I', 0)           # SizeOfUninitializedData
pe_bytes += struct.pack('<I', 0x1000)      # AddressOfEntryPoint
pe_bytes += struct.pack('<I', 0x1000)      # BaseOfCode
pe_bytes += struct.pack('<Q', 0x140000000) # ImageBase
pe_bytes += struct.pack('<I', 0x1000)      # SectionAlignment
pe_bytes += struct.pack('<I', 0x200)       # FileAlignment
pe_bytes += struct.pack('<H', 6)           # MajorOSVersion
pe_bytes += struct.pack('<H', 0)           # MinorOSVersion
pe_bytes += struct.pack('<H', 0)           # MajorImageVersion
pe_bytes += struct.pack('<H', 0)           # MinorImageVersion
pe_bytes += struct.pack('<H', 6)           # MajorSubsystemVersion
pe_bytes += struct.pack('<H', 0)           # MinorSubsystemVersion
pe_bytes += struct.pack('<I', 0)           # Win32VersionValue
pe_bytes += struct.pack('<I', 0x3000)      # SizeOfImage
pe_bytes += struct.pack('<I', 0x400)       # SizeOfHeaders
pe_bytes += struct.pack('<I', 0)           # CheckSum
pe_bytes += struct.pack('<H', 3)           # Subsystem: WINDOWS_CUI
pe_bytes += struct.pack('<H', 0)           # DllCharacteristics
pe_bytes += struct.pack('<Q', 0x100000)    # SizeOfStackReserve
pe_bytes += struct.pack('<Q', 0x1000)      # SizeOfStackCommit
pe_bytes += struct.pack('<Q', 0x100000)    # SizeOfHeapReserve
pe_bytes += struct.pack('<Q', 0x1000)      # SizeOfHeapCommit
pe_bytes += struct.pack('<I', 0)           # LoaderFlags
pe_bytes += struct.pack('<I', 16)          # NumberOfRvaAndSizes
# Data directories (16 × 8 bytes = 128 bytes)
pe_bytes += b'\x00' * 128

# Section Header (.text)
pe_bytes += b'.text\x00\x00\x00'          # Name (8 bytes)
pe_bytes += struct.pack('<I', 0x200)       # VirtualSize
pe_bytes += struct.pack('<I', 0x1000)      # VirtualAddress
pe_bytes += struct.pack('<I', 0x200)       # SizeOfRawData
pe_bytes += struct.pack('<I', 0x400)       # PointerToRawData
pe_bytes += struct.pack('<I', 0)           # PointerToRelocations
pe_bytes += struct.pack('<I', 0)           # PointerToLinenumbers
pe_bytes += struct.pack('<H', 0)           # NumberOfRelocations
pe_bytes += struct.pack('<H', 0)           # NumberOfLinenumbers
pe_bytes += struct.pack('<I', 0x60000020)  # Characteristics: CODE|EXECUTE|READ

# Pad to section raw offset (0x400)
pe_bytes += b'\x00' * (0x400 - len(pe_bytes))

# .text section content — test strings (analiz için)
section_data = b'\x00' * 32
section_data += b'http://malware-c2.example.com/gate.php\x00'
section_data += b'cmd.exe /c whoami\x00'
section_data += b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00'
section_data += b'VirtualAllocEx\x00'
section_data += b'WriteProcessMemory\x00'
section_data += b'IsDebuggerPresent\x00'
section_data += b'Mozilla/4.0 (compatible; MSIE 6.0)\x00'
section_data += b'\xde\xad\xbe\xef' * 64   # Simulated binary data
section_data = section_data[:0x200].ljust(0x200, b'\x00')

pe_bytes += section_data

with open('samples/demo_sample.bin', 'wb') as f:
    f.write(bytes(pe_bytes))

print(f"  Demo binary oluşturuldu: samples/demo_sample.bin ({len(pe_bytes)} bytes)")
PYEOF
}

run_analysis() {
    local target_file="$1"
    echo -e "\n${BOLD}[*] Analiz başlıyor: ${target_file}${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    mkdir -p "${REPORTS_DIR}"

    # Step 1: File info
    echo -e "\n${BOLD}[1/4] Dosya bilgileri${NC}"
    echo -e "  Boyut  : $(wc -c < "${target_file}") bytes"
    echo -e "  SHA256 : $(sha256sum "${target_file}" | cut -d' ' -f1)"
    echo -e "  MD5    : $(md5sum "${target_file}" | cut -d' ' -f1)"

    if command -v file &>/dev/null; then
        echo -e "  Tür    : $(file -b "${target_file}")"
    fi

    # Step 2: String extraction
    echo -e "\n${BOLD}[2/4] String extraction${NC}"
    python3 src/string_extractor.py "${target_file}" 2>/dev/null || \
        echo -e "${YELLOW}  [!] string_extractor.py hatası — devam ediliyor${NC}"

    # Step 3: Static analysis
    echo -e "\n${BOLD}[3/4] Static analysis (PE parser)${NC}"
    python3 src/pe_parser.py "${target_file}" 2>/dev/null || \
        echo -e "${YELLOW}  [!] PE parser hatası (PE formatı değil?) — devam ediliyor${NC}"

    # Step 4: Full analysis + report
    echo -e "\n${BOLD}[4/4] Rapor oluşturuluyor${NC}"
    python3 src/analyzer.py --file "${target_file}" --output "${REPORTS_DIR}" || {
        echo -e "${YELLOW}  [!] pefile kurulu değil — temel rapor üretiliyor${NC}"
        # Fallback: minimal rapor
        local base
        base=$(basename "${target_file}" | sed 's/\.[^.]*$//')
        {
            echo "# Static Analysis Report — ${base}"
            echo ""
            echo "**Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
            echo "**Analyst:** Semih Kaynar | Istinye University BGT210"
            echo ""
            echo "## File Info"
            echo "| Field | Value |"
            echo "|---|---|"
            echo "| File | \`$(basename "${target_file}")\` |"
            echo "| SHA256 | \`$(sha256sum "${target_file}" | cut -d' ' -f1)\` |"
            echo "| Size | $(wc -c < "${target_file}") bytes |"
            echo ""
            echo "## Strings (ASCII, min 6 chars)"
            echo "\`\`\`"
            strings -n 6 "${target_file}" 2>/dev/null | head -50
            echo "\`\`\`"
        } > "${REPORTS_DIR}/${base}_basic_report.md"
        echo -e "${GREEN}  [✓] Temel rapor: ${REPORTS_DIR}/${base}_basic_report.md${NC}"
    }
}

show_results() {
    echo -e "\n${CYAN}────────────────────────────────────────${NC}"
    echo -e "${BOLD}[*] Üretilen raporlar:${NC}"
    if ls "${REPORTS_DIR}"/*.md 2>/dev/null | head -10; then
        echo ""
        echo -e "${GREEN}[✓] Analiz tamamlandı!${NC}"
        echo -e "    Raporları görüntülemek için:"
        echo -e "    ${CYAN}→ Tarayıcıda aç: open reports/ (Mac) veya xdg-open reports/ (Linux)${NC}"
        echo -e "    ${CYAN}→ HTML rapor için: open report.html${NC}"
    else
        echo -e "${YELLOW}  Henüz rapor yok.${NC}"
    fi
}

# ── MAIN ──────────────────────────────────────────────────────

print_banner
check_python
check_dependencies

if [ $# -ge 1 ]; then
    # Gerçek dosya analizi
    if [ ! -f "$1" ]; then
        echo -e "${RED}[ERROR] Dosya bulunamadı: $1${NC}"
        exit 1
    fi
    run_analysis "$1"
else
    # Demo modu
    echo -e "\n${YELLOW}[*] Hedef dosya belirtilmedi — Demo modu başlatılıyor${NC}"
    echo -e "    Kullanım: ${CYAN}./run.sh <binary_dosya>${NC}\n"
    create_demo_binary
    run_analysis "${DEMO_BINARY}"
fi

show_results

echo -e "\n${BOLD}[*] BGT210 RE Framework — Semih Kaynar | Istinye University${NC}\n"
