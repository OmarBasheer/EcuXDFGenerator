"""
Checksum calculator for ECU binary files.

Algorithms implemented
  sum8         — 8-bit byte sum
  sum16        — 16-bit byte sum
  sum32        — 32-bit byte sum
  xor8         — XOR of all bytes
  negate_sum8  — ones-complement negation of 8-bit sum
  crc16        — CRC-16/CCITT-FALSE  (init=0xFFFF, poly=0x1021)
  crc32        — CRC-32/ISO-HDLC    (init=0xFFFFFFFF, poly=0xEDB88320)
  subaru       — Denso/Subaru: 32-bit sum + magic 0x5AA5A55A
  honda        — Honda OBD1/2: 8-bit 2's-complement sum

The `patch` method writes a corrected checksum into a copy of the binary.
"""

import base64
import struct
from typing import Any, Dict, Optional, Tuple


class ChecksumCalculator:
    _SUBARU_MAGIC = 0x5AA5A55A

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    # ------------------------------------------------------------------
    # Public: calculate all
    # ------------------------------------------------------------------

    def calculate_all(
        self,
        region_start: int = 0,
        region_end: Optional[int] = None,
    ) -> Dict[str, Any]:
        if region_end is None or region_end > self.size:
            region_end = self.size
        region = self.data[region_start:region_end]

        return {
            "region": {
                "start":     region_start,
                "start_hex": f"0x{region_start:X}",
                "end":       region_end,
                "end_hex":   f"0x{region_end:X}",
                "size":      len(region),
            },
            "sum8":        self._sum8(region),
            "sum16":       self._sum16(region),
            "sum32":       self._sum32(region),
            "xor8":        self._xor8(region),
            "negate_sum8": self._negate_sum8(region),
            "crc16":       self._crc16(region),
            "crc32":       self._crc32(region),
            "subaru":      self._subaru(region),
            "honda":       self._honda(region),
        }

    # ------------------------------------------------------------------
    # Algorithms (all accept a bytes slice)
    # ------------------------------------------------------------------

    @staticmethod
    def _sum8(data: bytes) -> Dict[str, Any]:
        v = sum(data) & 0xFF
        return {"value": f"0x{v:02X}", "decimal": v}

    @staticmethod
    def _sum16(data: bytes) -> Dict[str, Any]:
        v = sum(data) & 0xFFFF
        return {"value": f"0x{v:04X}", "decimal": v}

    @staticmethod
    def _sum32(data: bytes) -> Dict[str, Any]:
        v = sum(data) & 0xFFFFFFFF
        return {"value": f"0x{v:08X}", "decimal": v}

    @staticmethod
    def _xor8(data: bytes) -> Dict[str, Any]:
        v = 0
        for b in data:
            v ^= b
        return {"value": f"0x{v:02X}", "decimal": v}

    @staticmethod
    def _negate_sum8(data: bytes) -> Dict[str, Any]:
        v = (~sum(data)) & 0xFF
        return {"value": f"0x{v:02X}", "decimal": v}

    @staticmethod
    def _crc16(data: bytes) -> Dict[str, Any]:
        """CRC-16/CCITT-FALSE (init=0xFFFF, poly=0x1021, no reflect)."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        return {"value": f"0x{crc:04X}", "decimal": crc}

    @staticmethod
    def _crc32(data: bytes) -> Dict[str, Any]:
        """CRC-32/ISO-HDLC (init=0xFFFFFFFF, poly=0xEDB88320, reflect in/out)."""
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        v = crc ^ 0xFFFFFFFF
        return {"value": f"0x{v:08X}", "decimal": v}

    @classmethod
    def _subaru(cls, data: bytes) -> Dict[str, Any]:
        """Subaru/Denso: 32-bit byte sum + 0x5AA5A55A (mod 2^32)."""
        byte_sum = sum(data) & 0xFFFFFFFF
        v = (byte_sum + cls._SUBARU_MAGIC) & 0xFFFFFFFF
        return {
            "value":          f"0x{v:08X}",
            "decimal":        v,
            "byte_sum":       f"0x{byte_sum:08X}",
            "magic_constant": f"0x{cls._SUBARU_MAGIC:08X}",
            "description":    "SUM(all bytes) + 0x5AA5A55A  mod 2³²",
        }

    @staticmethod
    def _honda(data: bytes) -> Dict[str, Any]:
        """Honda OBD1/2: (0x100 − SUM(bytes)) mod 256."""
        s = sum(data) & 0xFF
        v = (0x100 - s) & 0xFF
        return {
            "value":       f"0x{v:02X}",
            "decimal":     v,
            "byte_sum":    f"0x{s:02X}",
            "description": "(0x100 − SUM(bytes)) mod 256  — 2's-complement",
        }

    # ------------------------------------------------------------------
    # Patch: write corrected checksum back into binary
    # ------------------------------------------------------------------

    def patch(self, algorithm: str, config: Dict) -> Tuple[bytes, Dict[str, Any]]:
        """
        Compute and write the checksum for the given algorithm.

        config keys (all optional, sensible defaults apply):
          file_data       — base64-encoded binary (used instead of self.data)
          region_start    — hex or int, default 0
          region_end      — hex or int, default end of file
          storage_address — hex or int, where to write the checksum
        """
        raw = base64.b64decode(config["file_data"]) if "file_data" in config else self.data
        data = bytearray(raw)

        def _addr(key: str, default: int) -> int:
            v = config.get(key, default)
            if isinstance(v, str):
                return int(v, 16) if v.strip().lower().startswith("0x") else int(v)
            return int(v)

        r_start  = _addr("region_start",    0)
        r_end    = _addr("region_end",       len(data))
        stor     = _addr("storage_address",  len(data) - 4)

        if algorithm == "subaru":
            # Exclude the 4-byte storage slot from the checksummed region
            region = bytes(data[r_start:stor]) + bytes(data[stor + 4: r_end])
            byte_sum = sum(region) & 0xFFFFFFFF
            csum = (byte_sum + self._SUBARU_MAGIC) & 0xFFFFFFFF
            data[stor: stor + 4] = struct.pack("<I", csum)
            return bytes(data), {
                "algorithm":      "subaru",
                "checksum":       f"0x{csum:08X}",
                "storage_address": f"0x{stor:X}",
            }

        if algorithm == "honda":
            region = bytes(data[r_start: r_end - 1])
            s = sum(region) & 0xFF
            csum = (0x100 - s) & 0xFF
            data[stor] = csum
            return bytes(data), {
                "algorithm":      "honda",
                "checksum":       f"0x{csum:02X}",
                "storage_address": f"0x{stor:X}",
            }

        if algorithm == "crc32":
            region = bytes(data[r_start: r_end])
            crc = 0xFFFFFFFF
            for byte in region:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
            csum = crc ^ 0xFFFFFFFF
            data[stor: stor + 4] = struct.pack("<I", csum)
            return bytes(data), {
                "algorithm":      "crc32",
                "checksum":       f"0x{csum:08X}",
                "storage_address": f"0x{stor:X}",
            }

        if algorithm == "sum32":
            region = bytes(data[r_start: r_end])
            csum = sum(region) & 0xFFFFFFFF
            data[stor: stor + 4] = struct.pack("<I", csum)
            return bytes(data), {
                "algorithm":      "sum32",
                "checksum":       f"0x{csum:08X}",
                "storage_address": f"0x{stor:X}",
            }

        if algorithm == "sum16":
            region = bytes(data[r_start: r_end])
            csum = sum(region) & 0xFFFF
            data[stor: stor + 2] = struct.pack("<H", csum)
            return bytes(data), {
                "algorithm":      "sum16",
                "checksum":       f"0x{csum:04X}",
                "storage_address": f"0x{stor:X}",
            }

        raise ValueError(f"Unknown checksum algorithm: {algorithm!r}")
