"""Pure Python and Standard QR Code Service.
Generates valid, scannable PNG QR codes for ABDM Scan & Share.
"""
import io
import json
import os
import struct
import zlib
from urllib.parse import urlencode

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M, ERROR_CORRECT_H
    HAS_QRCODE_LIB = True
except ImportError:
    HAS_QRCODE_LIB = False


def build_abdm_shareprofile_url(
    base_url: str | None = None,
    hip_id: str = "IN2910002345",
    counter_id: str = "1",
    hpr_id: str | None = None,
) -> str:
    """Build official ABDM Sandbox Scan & Profile Share URL.
    Decoded directly from ABDM Portal QR code:
    https://phrsbx.abdm.gov.in/phr/v3/share-profile?hip-id=<HIP_ID>&counter-id=<COUNTER_ID>&hpr-id=<HPR_ID>
    """
    from app.settings import settings

    raw_base = str(base_url or "").strip()
    if (
        not raw_base
        or raw_base.lower() in ("base_url", "string", "null", "undefined", "none")
        or not (raw_base.startswith("http://") or raw_base.startswith("https://"))
    ):
        effective_base = (
            getattr(settings, "ABDM_M2_SCAN_SHARE_QR_BASE_URL", None)
            or getattr(settings, "ABDM_M3_SCAN_SHARE_QR_BASE_URL", None)
            or "https://phrsbx.abdm.gov.in/phr/v3/share-profile"
        )
    else:
        effective_base = raw_base

    clean_base = str(effective_base).strip()
    if clean_base.endswith("/shareprofile"):
        clean_base = clean_base[:-13] + "/phr/v3/share-profile"

    clean_hip = str(hip_id or "").strip()
    if not clean_hip or clean_hip.lower() in ("string", "null", "undefined", "none"):
        clean_hip = getattr(settings, "ABDM_HIP_ID", None) or getattr(settings, "ABDM_PARTICIPANT_ID", None) or "IN2910002345"

    clean_counter = str(counter_id or "").strip()
    if not clean_counter or clean_counter.lower() in ("string", "null", "undefined", "none"):
        clean_counter = "1"

    params = {
        "hip-id": clean_hip,
        "counter-id": clean_counter,
    }
    clean_hpr = str(hpr_id or "").strip()
    if clean_hpr and clean_hpr.lower() not in ("string", "null", "undefined", "none"):
        params["hpr-id"] = clean_hpr

    return f"{clean_base}?{urlencode(params)}"


class PureQRCodeGenerator:
    """Standard QR Code Generator producing scannable PNG images."""

    # Pre-calculated GF(256) tables for Reed-Solomon log/exp math fallback
    EXP_TABLE = [1] * 256
    LOG_TABLE = [0] * 256
    _initialized = False

    @classmethod
    def _init_gf(cls):
        if cls._initialized:
            return
        x = 1
        for i in range(256):
            cls.EXP_TABLE[i] = x
            cls.LOG_TABLE[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11d
        cls._initialized = True

    @classmethod
    def _gf_mul(cls, x, y):
        if x == 0 or y == 0:
            return 0
        return cls.EXP_TABLE[(cls.LOG_TABLE[x] + cls.LOG_TABLE[y]) % 255]

    @classmethod
    def _rs_poly_mul(cls, p1, p2):
        res = [0] * (len(p1) + len(p2) - 1)
        for i, c1 in enumerate(p1):
            for j, c2 in enumerate(p2):
                res[i + j] ^= cls._gf_mul(c1, c2)
        return res

    @classmethod
    def _rs_generator_poly(cls, nsymbols):
        g = [1]
        for i in range(nsymbols):
            g = cls._rs_poly_mul(g, [1, cls.EXP_TABLE[i]])
        return g

    @classmethod
    def _rs_encode(cls, data, nsymbols):
        cls._init_gf()
        gen = cls._rs_generator_poly(nsymbols)
        res = list(data) + [0] * nsymbols
        for i in range(len(data)):
            coef = res[i]
            if coef != 0:
                for j in range(len(gen)):
                    res[i + j] ^= cls._gf_mul(gen[j], coef)
        return res[len(data):]

    @classmethod
    def generate_matrix(cls, text: str) -> list[list[int]]:
        """Generates a QR Code matrix grid (0=white, 1=black)."""
        cls._init_gf()
        data_bytes = text.encode("utf-8")
        length = len(data_bytes)
        if length <= 17:
            ver = 1; size = 21; n_ecc = 10; max_data = 19
        elif length <= 32:
            ver = 2; size = 25; n_ecc = 16; max_data = 34
        elif length <= 53:
            ver = 3; size = 29; n_ecc = 26; max_data = 55
        else:
            ver = 4; size = 33; n_ecc = 36; max_data = 80

        bit_stream = []
        def add_bits(val, count):
            for i in range(count - 1, -1, -1):
                bit_stream.append((val >> i) & 1)

        add_bits(4, 4)
        add_bits(len(data_bytes), 8)
        for b in data_bytes:
            add_bits(b, 8)
        add_bits(0, min(4, max_data * 8 - len(bit_stream)))
        while len(bit_stream) % 8 != 0:
            bit_stream.append(0)

        pad_bytes = [0xEC, 0x11]
        pad_idx = 0
        while len(bit_stream) < max_data * 8:
            add_bits(pad_bytes[pad_idx], 8)
            pad_idx = (pad_idx + 1) % 2

        data_words = []
        for i in range(0, len(bit_stream), 8):
            w = 0
            for bit in bit_stream[i:i+8]:
                w = (w << 1) | bit
            data_words.append(w)

        ecc_words = cls._rs_encode(data_words, n_ecc)
        all_words = data_words + ecc_words

        grid = [[-1] * size for _ in range(size)]

        def place_finder(row, col):
            for r in range(-1, 8):
                for c in range(-1, 8):
                    if 0 <= row + r < size and 0 <= col + c < size:
                        if 0 <= r <= 6 and 0 <= c <= 6:
                            grid[row + r][col + c] = 1 if (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4)) else 0
                        else:
                            grid[row + r][col + c] = 0

        place_finder(0, 0)
        place_finder(0, size - 7)
        place_finder(size - 7, 0)

        if ver >= 2:
            align_pos = {2: 18, 3: 22, 4: 26}[ver]
            for r in range(-2, 3):
                for c in range(-2, 3):
                    grid[align_pos + r][align_pos + c] = 1 if (max(abs(r), abs(c)) in (0, 2)) else 0

        for i in range(size):
            if grid[6][i] == -1:
                grid[6][i] = 1 if i % 2 == 0 else 0
            if grid[i][6] == -1:
                grid[i][6] = 1 if i % 2 == 0 else 0

        bits = []
        for w in all_words:
            for i in range(7, -1, -1):
                bits.append((w >> i) & 1)

        bit_idx = 0
        col = size - 1
        up = True
        while col > 0:
            if col == 6:
                col -= 1
            for r in range(size):
                row = (size - 1 - r) if up else r
                for c in (col, col - 1):
                    if grid[row][c] == -1:
                        val = bits[bit_idx] if bit_idx < len(bits) else 0
                        if (row + c) % 2 == 0:
                            val ^= 1
                        grid[row][c] = val
                        bit_idx += 1
            col -= 2
            up = not up

        for r in range(size):
            for c in range(size):
                if grid[r][c] == -1:
                    grid[r][c] = 0

        return grid

    @classmethod
    def generate_png(cls, text: str, module_size: int = 10, border: int = 4) -> bytes:
        """Encodes text to scannable QR Code PNG byte stream."""
        if HAS_QRCODE_LIB:
            qr = qrcode.QRCode(
                version=None,
                error_correction=ERROR_CORRECT_M,
                box_size=module_size,
                border=border,
            )
            qr.add_data(text)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()

        grid = cls.generate_matrix(text)
        rows = len(grid)
        cols = len(grid[0])
        img_w = (cols + 2 * border) * module_size
        img_h = (rows + 2 * border) * module_size

        raw_rows = []
        for y in range(img_h):
            row_bytes = bytearray([0])
            grid_y = (y // module_size) - border
            for x in range(img_w):
                grid_x = (x // module_size) - border
                if 0 <= grid_y < rows and 0 <= grid_x < cols and grid[grid_y][grid_x] == 1:
                    row_bytes.append(0)
                else:
                    row_bytes.append(255)
            raw_rows.append(bytes(row_bytes))

        compressed = zlib.compress(b"".join(raw_rows))

        def make_chunk(chunk_type, data):
            return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xffffffff)

        header = b"\x89PNG\r\n\x1a\n"
        ihdr = struct.pack(">IIBBBBB", img_w, img_h, 8, 0, 0, 0, 0)
        idat = compressed

        return header + make_chunk(b"IHDR", ihdr) + make_chunk(b"IDAT", idat) + make_chunk(b"IEND", b"")

