
import base64
import struct
import os

# Valid 1x1 PNG (Red pixel)
PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
png_data = base64.b64decode(PNG_B64)

# Write PNG files
with open("src-tauri/icons/icon.png", "wb") as f:
    f.write(png_data)
with open("src-tauri/icons/32x32.png", "wb") as f:
    f.write(png_data)
with open("src-tauri/icons/128x128.png", "wb") as f:
    f.write(png_data)
with open("src-tauri/icons/128x128@2x.png", "wb") as f:
    f.write(png_data)

# Construct valid ICO wrapper for the PNG
# Header: Reserved(2)=0, Type(2)=1(ICO), Count(2)=1
header = struct.pack('<HHH', 0, 1, 1)

# Directory Entry: W(1), H(1), Colors(1), Res(1), Planes(2), BPP(2), Size(4), Offset(4)
# 1x1 pixel image
entry = struct.pack('<BBBBHHII', 
    1, 1, 0, 0,  # w, h, colors, reserved
    1, 32,       # planes, bpp
    len(png_data), # size
    22           # offset (6 + 16)
)

with open("src-tauri/icons/icon.ico", "wb") as f:
    f.write(header)
    f.write(entry)
    f.write(png_data)

print("Fixed icons with valid ICO container.")
