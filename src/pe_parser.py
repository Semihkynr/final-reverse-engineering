#!/usr/bin/env python3
"""
PE Format Parser — detailed PE structure extraction
BGT210 - Istinye University | Semih Kaynar
"""

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float

    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    def is_readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)


@dataclass
class ImportEntry:
    dll: str
    functions: list = field(default_factory=list)


@dataclass
class PEInfo:
    architecture: str
    timestamp: int
    subsystem: str
    entry_point: int
    image_base: int
    sections: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    is_dll: bool = False
    is_packed: bool = False


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_pe(filepath: str) -> Optional[PEInfo]:
    """
    Manual PE parser — extracts key header fields without external libs.
    For full analysis, use pefile library (see analyzer.py).
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(filepath)

    data = path.read_bytes()

    # MZ signature check
    if data[:2] != b"MZ":
        return None

    # e_lfanew offset (PE header pointer at 0x3C)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # PE signature check
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff_offset = e_lfanew + 4

    # COFF File Header
    machine = struct.unpack_from("<H", data, coff_offset)[0]
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    timestamp = struct.unpack_from("<I", data, coff_offset + 4)[0]
    characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
    optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]

    arch_map = {0x014C: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)", 0xAA64: "ARM64"}
    architecture = arch_map.get(machine, f"Unknown (0x{machine:04x})")

    is_dll = bool(characteristics & 0x2000)

    # Optional Header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_pe32_plus = magic == 0x20B

    subsystem_map = {
        1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
        9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 14: "XBOX",
    }

    if is_pe32_plus:
        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        subsystem_raw = struct.unpack_from("<H", data, opt_offset + 68)[0]
    else:
        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
        subsystem_raw = struct.unpack_from("<H", data, opt_offset + 68)[0]

    subsystem = subsystem_map.get(subsystem_raw, f"Unknown ({subsystem_raw})")

    # Section Headers
    section_table_offset = opt_offset + optional_header_size
    sections = []
    high_entropy_count = 0

    for i in range(num_sections):
        sec_offset = section_table_offset + i * 40
        name_raw = data[sec_offset:sec_offset + 8]
        name = name_raw.rstrip(b"\x00").decode(errors="replace")

        virtual_size = struct.unpack_from("<I", data, sec_offset + 8)[0]
        virtual_address = struct.unpack_from("<I", data, sec_offset + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
        raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]
        sec_characteristics = struct.unpack_from("<I", data, sec_offset + 36)[0]

        if raw_offset and raw_size:
            sec_data = data[raw_offset:raw_offset + raw_size]
            entropy = _calculate_entropy(sec_data)
        else:
            entropy = 0.0

        if entropy > 7.0:
            high_entropy_count += 1

        sections.append(SectionInfo(
            name=name,
            virtual_address=virtual_address,
            virtual_size=virtual_size,
            raw_size=raw_size,
            raw_offset=raw_offset,
            characteristics=sec_characteristics,
            entropy=entropy,
        ))

    is_packed = high_entropy_count > 0

    return PEInfo(
        architecture=architecture,
        timestamp=timestamp,
        subsystem=subsystem,
        entry_point=entry_point,
        image_base=image_base,
        sections=sections,
        is_dll=is_dll,
        is_packed=is_packed,
    )


def print_pe_summary(pe: PEInfo):
    print(f"Architecture : {pe.architecture}")
    print(f"Entry Point  : 0x{pe.entry_point:08x}")
    print(f"Image Base   : 0x{pe.image_base:x}")
    print(f"Subsystem    : {pe.subsystem}")
    print(f"Is DLL       : {pe.is_dll}")
    print(f"Packed       : {pe.is_packed}")
    print()
    print(f"{'Section':<12} {'VirtAddr':<12} {'RawSize':<10} {'Entropy':<8} {'Flags'}")
    print("-" * 60)
    for sec in pe.sections:
        flags = ""
        if sec.is_executable():
            flags += "X"
        if sec.is_writable():
            flags += "W"
        if sec.is_readable():
            flags += "R"
        warn = " ⚠ HIGH ENTROPY" if sec.entropy > 7.0 else ""
        print(f"{sec.name:<12} 0x{sec.virtual_address:08x}   {sec.raw_size:<10} {sec.entropy:<8}{flags}{warn}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python pe_parser.py <file>")
        sys.exit(1)

    result = parse_pe(sys.argv[1])
    if result is None:
        print("[-] Not a valid PE file.")
        sys.exit(1)

    print_pe_summary(result)
