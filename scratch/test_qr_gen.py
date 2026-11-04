import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.qr_service import PureQRCodeGenerator

text = "https://phrsbx.abdm.gov.in/share-profile?hip-id=IN2910002345&counter-id=1"
png_bytes = PureQRCodeGenerator.generate_png(text)
print(f"Generated PNG Bytes Length: {len(png_bytes)}")
print("PNG Header Check:", png_bytes.startswith(b"\x89PNG\r\n\x1a\n"))
