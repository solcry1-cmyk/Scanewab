# fix_unicode.py
import re

# Path ke file toolkit.py
file_path = "toolkit.py"

# Buka file dan baca isinya
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Ganti karakter bermasalah
replacements = {
    "‑": "-",   # non-breaking hyphen → minus biasa
    "→": "->",  # panah kanan → ASCII arrow
}

for old, new in replacements.items():
    content = content.replace(old, new)

# Simpan kembali
with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Selesai! Semua karakter non-ASCII diganti dengan ASCII.")
