"""
Binary analyzer for ECU ROM files.

Scans the binary for:
  - File metadata (size, hash, fill byte)
  - ECU type hints (size-based + signature-based)
  - Region classification by Shannon entropy (code vs data)
  - Potential axis / breakpoint arrays
  - Potential calibration tables
  - Checksum storage hints
  - ASCII strings / signatures
"""

import hashlib
import math
from collections import Counter
from typing import Any, Dict, List, Optional


class BinaryAnalyzer:
    # --- size → description mapping ----------------------------------------
    SIZE_MAP = {
        0x8000:   "Generic 32 KB ECU",
        0x10000:  "Generic 64 KB ECU",
        0x20000:  "Generic 128 KB ECU / Older Honda OBD1",
        0x40000:  "Honda OBD1 256 KB (P28 / P30 / P72)",
        0x80000:  "Honda OBD2 512 KB / Generic 512 KB",
        0x100000: "Hyundai/Kia Theta-II SIM2k-250 / Subaru EJ / Mitsubishi EVO — 1 MB",
        0x180000: "Mitsubishi / Denso 1.5 MB",
        0x200000: "Modern ECU 2 MB",
        0x400000: "Modern ECU 4 MB",
    }

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        return {
            "file_info":       self._file_info(),
            "suggested_ecu":   self._detect_ecu_type(),
            "regions":         self._analyze_regions(),
            "potential_axes":  self._find_potential_axes(),
            "potential_tables": self._find_potential_tables(),
            "checksum_hints":  self._detect_checksum_hints(),
            "signatures":      self._find_signatures(),
        }

    # -----------------------------------------------------------------------
    # File info
    # -----------------------------------------------------------------------

    def _file_info(self) -> Dict[str, Any]:
        fill = self._detect_fill_byte()
        return {
            "size":     self.size,
            "size_hex": f"0x{self.size:X}",
            "size_kb":  self.size // 1024,
            "md5":      hashlib.md5(self.data).hexdigest(),
            "sha1":     hashlib.sha1(self.data).hexdigest(),
            "fill_byte": f"0x{fill:02X}" if fill is not None else None,
        }

    def _detect_fill_byte(self) -> Optional[int]:
        counts = Counter(self.data)
        most_common_val, most_common_cnt = counts.most_common(1)[0]
        if most_common_cnt > self.size * 0.30:
            return most_common_val
        return None

    # -----------------------------------------------------------------------
    # ECU type detection
    # -----------------------------------------------------------------------

    def _detect_ecu_type(self) -> Dict[str, Any]:
        primary = self.SIZE_MAP.get(
            self.size,
            f"Unknown size — {self.size} bytes (0x{self.size:X} / {self.size // 1024} KB)",
        )
        suggestions: List[str] = []

        # Hyundai/Kia SIM2k-250 signatures
        for sig in (b"SIM2K", b"SIM2k", b"HMC", b"HYUNDAI", b"MOBIS"):
            idx = self.data.find(sig)
            if idx >= 0:
                suggestions.append(
                    f"{sig.decode()} string found at 0x{idx:X} — likely Hyundai/Kia SIM2k-250"
                )

        # Subaru/Denso magic constant
        if b"\x5A\xA5\xA5\x5A" in self.data:
            suggestions.append("Subaru / Denso (checksum marker 0x5AA5A55A found)")

        # ASCII manufacturer strings
        for sig in (b"SUBARU", b"HONDA", b"DENSO", b"BOSCH", b"SIEMENS", b"MOTOROLA"):
            idx = self.data.find(sig)
            if idx >= 0:
                suggestions.append(f"{sig.decode()} string found at 0x{idx:X}")

        return {
            "primary":     primary,
            "suggestions": suggestions,
            "profiles":    self._matching_profile_ids(),
        }

    def _matching_profile_ids(self) -> List[str]:
        from xdf.profiles import ECU_PROFILES
        return [p["id"] for p in ECU_PROFILES if self.size in p.get("binary_sizes", [])]

    # -----------------------------------------------------------------------
    # Entropy-based region classification
    # -----------------------------------------------------------------------

    def _analyze_regions(self) -> List[Dict[str, Any]]:
        block_size = max(0x400, min(0x1000, self.size // 16))
        raw: List[Dict[str, Any]] = []

        for offset in range(0, self.size, block_size):
            end = min(offset + block_size, self.size)
            block = self.data[offset:end]
            entropy = self._entropy(block)
            raw.append({
                "start":     offset,
                "start_hex": f"0x{offset:X}",
                "end":       end,
                "end_hex":   f"0x{end:X}",
                "size":      end - offset,
                "entropy":   round(entropy, 3),
                "type":      self._classify_entropy(entropy),
            })

        return self._merge_regions(raw)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    @staticmethod
    def _classify_entropy(entropy: float) -> str:
        if entropy < 1.0:
            return "empty"   # fill bytes
        if entropy < 4.5:
            return "data"    # structured calibration data
        if entropy < 6.5:
            return "mixed"
        return "code"

    @staticmethod
    def _merge_regions(regions: List[Dict]) -> List[Dict]:
        if not regions:
            return []
        merged = [dict(regions[0])]
        for r in regions[1:]:
            if r["type"] == merged[-1]["type"]:
                merged[-1]["end"]     = r["end"]
                merged[-1]["end_hex"] = r["end_hex"]
                merged[-1]["size"]   += r["size"]
                merged[-1]["entropy"] = round(
                    (merged[-1]["entropy"] + r["entropy"]) / 2, 3
                )
            else:
                merged.append(dict(r))
        return merged

    # -----------------------------------------------------------------------
    # Axis / breakpoint detection
    # -----------------------------------------------------------------------

    def _find_potential_axes(self) -> List[Dict[str, Any]]:
        axes: List[Dict[str, Any]] = []
        seen: set = set()
        scan_limit = min(self.size, 0x40000)
        LENGTHS = [6, 8, 10, 12, 14, 16, 18, 20, 24, 32]

        # 8-bit axes — scan every 4 bytes
        for start in range(0, scan_limit - 32, 4):
            for length in LENGTHS:
                if start + length > self.size:
                    break
                seq = list(self.data[start: start + length])
                if self._valid_axis_8(seq) and start not in seen:
                    seen.add(start)
                    axes.append({
                        "address":     start,
                        "address_hex": f"0x{start:X}",
                        "count":       length,
                        "element_size": 8,
                        "values":      seq,
                        "type":        self._classify_axis_8(seq),
                    })
                    break

        # 16-bit axes — scan every 4 bytes (2-byte aligned)
        for start in range(0, scan_limit - 64, 4):
            for length in LENGTHS:
                if start + length * 2 > self.size:
                    break
                seq = [
                    int.from_bytes(self.data[start + i * 2: start + i * 2 + 2], "big")
                    for i in range(length)
                ]
                if self._valid_axis_16(seq) and start not in seen:
                    seen.add(start)
                    axes.append({
                        "address":     start,
                        "address_hex": f"0x{start:X}",
                        "count":       length,
                        "element_size": 16,
                        "values":      seq,
                        "type":        self._classify_axis_16(seq),
                    })
                    break

        axes.sort(key=lambda x: x["address"])
        return axes[:80]

    @staticmethod
    def _valid_axis_8(seq: List[int]) -> bool:
        if len(seq) < 4:
            return False
        # strictly monotonic increasing
        for i in range(1, len(seq)):
            if seq[i] <= seq[i - 1]:
                return False
        if seq[0] == 0xFF:
            return False
        if seq[-1] - seq[0] < 20:
            return False
        deltas = [seq[i] - seq[i - 1] for i in range(1, len(seq))]
        mean = sum(deltas) / len(deltas)
        if mean == 0:
            return False
        if max(abs(d - mean) / mean for d in deltas) > 3.0:
            return False
        return True

    @staticmethod
    def _valid_axis_16(seq: List[int]) -> bool:
        if len(seq) < 4:
            return False
        for i in range(1, len(seq)):
            if seq[i] <= seq[i - 1]:
                return False
        if seq[-1] > 65000 or seq[0] > 10000:
            return False
        if seq[-1] - seq[0] < 100:
            return False
        deltas = [seq[i] - seq[i - 1] for i in range(1, len(seq))]
        mean = sum(deltas) / len(deltas)
        if mean == 0:
            return False
        if max(abs(d - mean) / mean for d in deltas) > 3.0:
            return False
        return True

    @staticmethod
    def _classify_axis_8(seq: List[int]) -> str:
        first, last = seq[0], seq[-1]
        if first == 0 and last <= 100:
            return "tps_load_pct"
        if first == 0 and last <= 255:
            return "generic_8bit"
        return "unknown_8bit"

    @staticmethod
    def _classify_axis_16(seq: List[int]) -> str:
        deltas = [seq[i] - seq[i - 1] for i in range(1, len(seq))]
        mean = sum(deltas) / len(deltas)
        if seq[0] <= 500 and seq[-1] > 1000 and 200 <= mean <= 1000:
            return "rpm"
        if seq[0] == 0 and seq[-1] <= 2000 and mean < 200:
            return "map_kpa"
        if seq[-1] > 3000:
            return "rpm"
        return "unknown_16bit"

    # -----------------------------------------------------------------------
    # Table detection
    # -----------------------------------------------------------------------

    def _find_potential_tables(self) -> List[Dict[str, Any]]:
        tables: List[Dict[str, Any]] = []
        regions = self._analyze_regions()
        data_regions = [r for r in regions if r["type"] in ("data", "mixed")]

        for region in data_regions[:6]:
            start = region["start"]
            end   = min(region["end"], start + 0x4000)
            tables.extend(self._tables_in_region(start, end))
            if len(tables) >= 30:
                break

        return tables[:30]

    _COMMON_DIMS = [
        (8, 8), (8, 16), (16, 8), (16, 16),
        (12, 12), (16, 20), (20, 16),
        (32, 1), (1, 32),
    ]

    def _tables_in_region(self, start: int, end: int) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for rows, cols in self._COMMON_DIMS:
            cell_count = rows * cols
            step = max(1, cell_count // 4)
            for addr in range(start, end - cell_count, step):
                block = self.data[addr: addr + cell_count]
                if len(block) < cell_count:
                    break
                if self._looks_like_table(block, rows, cols):
                    found.append({
                        "address":      addr,
                        "address_hex":  f"0x{addr:X}",
                        "rows":         rows,
                        "cols":         cols,
                        "element_size": 8,
                        "size":         cell_count,
                        "sample":       list(block[:min(16, cell_count)]),
                        "label":        f"{rows}×{cols} table",
                    })
        return found

    @staticmethod
    def _looks_like_table(data: bytes, rows: int, cols: int) -> bool:
        n = rows * cols
        if len(data) < n:
            return False
        entropy = BinaryAnalyzer._entropy(data[:n])
        if entropy < 0.8 or entropy > 6.5:
            return False
        unique = len(set(data[:n]))
        if unique < 4:
            return False
        if max(data[:n]) - min(data[:n]) < 10:
            return False
        return True

    # -----------------------------------------------------------------------
    # Checksum hints
    # -----------------------------------------------------------------------

    def _detect_checksum_hints(self) -> List[Dict[str, Any]]:
        hints: List[Dict[str, Any]] = []

        # Subaru/Denso magic constant occurrences
        magic = b"\x5A\xA5\xA5\x5A"
        pos = 0
        while True:
            idx = self.data.find(magic, pos)
            if idx < 0:
                break
            hints.append({
                "address":     idx,
                "address_hex": f"0x{idx:X}",
                "type":        "subaru_magic",
                "description": "Subaru/Denso checksum magic 0x5AA5A55A",
            })
            pos = idx + 4

        # Size-based typical locations
        if self.size == 0x100000:
            hints.append({
                "address":     0xFFFC,
                "address_hex": "0xFFFC",
                "type":        "typical_1mb",
                "description": (
                    "Typical 1 MB checksum location (last 4 bytes of lower 64 KB block) — "
                    "applies to Subaru EJ, Mitsubishi EVO, and Hyundai/Kia SIM2k-250"
                ),
            })
        elif self.size == 0x80000:
            hints.append({
                "address":     0x7FFFC,
                "address_hex": "0x7FFFC",
                "type":        "typical_512kb",
                "description": "Typical 512 KB ROM checksum location",
            })

        # Probe 4-byte values near end of file
        for addr in (self.size - 4, self.size - 8, self.size - 256):
            if addr > 0 and addr + 4 <= self.size:
                val = int.from_bytes(self.data[addr: addr + 4], "little")
                if val not in (0x00000000, 0xFFFFFFFF):
                    hints.append({
                        "address":     addr,
                        "address_hex": f"0x{addr:X}",
                        "type":        "possible_32bit_checksum",
                        "description": f"Possible 32-bit checksum stored here (value 0x{val:08X})",
                    })

        return hints

    # -----------------------------------------------------------------------
    # ASCII / binary signatures
    # -----------------------------------------------------------------------

    def _find_signatures(self) -> List[Dict[str, Any]]:
        sigs: List[Dict[str, Any]] = []
        limit = min(self.size, 0x10000)
        i = 0
        while i < limit:
            if 0x20 <= self.data[i] <= 0x7E:
                j = i
                while j < limit and 0x20 <= self.data[j] <= 0x7E:
                    j += 1
                if j - i >= 4:
                    text = self.data[i:j].decode("ascii", errors="replace")
                    sigs.append({
                        "address":     i,
                        "address_hex": f"0x{i:X}",
                        "type":        "ascii_string",
                        "value":       text[:80],
                    })
                i = j
            else:
                i += 1
        return sigs[:20]
