import zlib
import struct
import base64
import json
import io

def generate_png_from_grid(grid, module_size=10, border=4):
    """Encodes a 2D 0/1 module grid into a clean, valid PNG byte array without third-party dependencies."""
    rows = len(grid)
    cols = len(grid[0]) if rows > 0 else 0
    img_w = (cols + 2 * border) * module_size
    img_h = (rows + 2 * border) * module_size

    # Raw grayscale scanlines (1 byte per pixel: 0=black, 255=white)
    raw_rows = []
    for y in range(img_h):
        row_bytes = bytearray([0]) # Filter type 0 (None)
        grid_y = (y // module_size) - border
        for x in range(img_w):
            grid_x = (x // module_size) - border
            if 0 <= grid_y < rows and 0 <= grid_x < cols and grid[grid_y][grid_x] == 1:
                row_bytes.append(0) # Black module
            else:
                row_bytes.append(255) # White background / border
        raw_rows.append(bytes(row_bytes))

    compressed = zlib.compress(b"".join(raw_rows))

    def make_chunk(chunk_type, data):
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xffffffff)

    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", img_w, img_h, 8, 0, 0, 0, 0)
    idat = compressed

    png_bytes = header + make_chunk(b"IHDR", ihdr) + make_chunk(b"IDAT", idat) + make_chunk(b"IEND", b"")
    return png_bytes

print("PNG generator script loaded cleanly!")
