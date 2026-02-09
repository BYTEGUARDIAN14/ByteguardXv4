
import urllib.request
import ssl
import shutil
import os

# Ignore SSL errors
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Download valid ICO
url = 'https://www.google.com/favicon.ico'
icon_path = 'src-tauri/icons/icon.ico'
png_path = 'src-tauri/icons/icon.png'

print(f"Downloading {url} to {icon_path}...")
urllib.request.urlretrieve(url, icon_path)

# Copy to other required names to be safe
shutil.copy(icon_path, png_path)
shutil.copy(icon_path, 'src-tauri/icons/32x32.png')
shutil.copy(icon_path, 'src-tauri/icons/128x128.png')
shutil.copy(icon_path, 'src-tauri/icons/128x128@2x.png')

print("Icons created successfully.")
