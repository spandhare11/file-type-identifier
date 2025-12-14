
#!/usr/bin/env python3
# File Type Identifier using Magic Numbers
# Features:
# - Offset-aware magic numbers
# - ASCII / UTF-8 text detection
# - Shebang (executable script) detection
# - Security-focused risk analysis

import sys
import json
import os


# -------------------------------
# Load magic number database
# -------------------------------
def load_magic_db():
    with open("magic_number.json", "r") as f:
        return json.load(f)


# -------------------------------
# Read magic number at given offset
# -------------------------------
def read_magic_at_offset(file_path, offset, length):
    with open(file_path, "rb") as f:
        f.seek(offset)
        return f.read(length).hex().upper()


# -------------------------------
# ASCII / UTF-8 text detection
# -------------------------------
def is_text_file(file_path, sample_size=512):
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)

        if not chunk:
            return False, None

        # UTF-8 BOM
        if chunk.startswith(b"\xef\xbb\xbf"):
            return True, "UTF-8 TEXT (BOM)"

        # Heuristic: mostly printable characters
        text_chars = bytearray(
            {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100))
        )
        non_text = chunk.translate(None, text_chars)

        if len(non_text) / len(chunk) < 0.05:
            return True, "ASCII / UTF-8 TEXT"

    except Exception:
        pass

    return False, None


# -------------------------------
# Shebang detection
# -------------------------------
def detect_shebang(file_path):
    try:
        with open(file_path, "rb") as f:
            first_line = f.readline(128)

        if first_line.startswith(b"#!"):
            decoded = first_line.decode(errors="ignore").strip()
            return True, decoded

    except Exception:
        pass

    return False, None


# -------------------------------
# Detect file type
# -------------------------------
def detect_file_type(file_path, magic_db):
    # 1️⃣ Binary magic number detection
    for filetype, data in magic_db.items():
        magic = data["magic"]
        offset = data["offset"]
        magic_len = len(magic) // 2

        file_magic = read_magic_at_offset(file_path, offset, magic_len)
        if file_magic.startswith(magic):
            return filetype, magic, offset

    # 2️⃣ Text detection
    is_text, text_type = is_text_file(file_path)
    if is_text:
        # 3️⃣ Shebang detection (script execution risk)
        has_shebang, shebang = detect_shebang(file_path)
        if has_shebang:
            return f"SCRIPT FILE ({shebang})", None, None

        return text_type, None, None

    return "UNKNOWN", None, None


# -------------------------------
# Risk analysis logic
# -------------------------------
def risk_analysis(extension, detected_type):
    if detected_type == "UNKNOWN":
        return "MEDIUM", "Unknown file signature"

    if detected_type.startswith("SCRIPT FILE"):
        return "HIGH", "Executable script masquerading detected"

    if "TEXT" in detected_type and extension not in ["TXT", "MD", "CSV", "LOG"]:
        return "HIGH", "Text-based file masquerading detected"

    if extension != detected_type and not detected_type.startswith("ASCII"):
        return "HIGH", "File masquerading detected"

    return "LOW", "File appears legitimate"


# -------------------------------
# Main function
# -------------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <file>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print("[!] File not found")
        sys.exit(1)

    magic_db = load_magic_db()
    detected_type, matched_magic, offset = detect_file_type(file_path, magic_db)
    extension = os.path.splitext(file_path)[1].replace(".", "").upper()

    risk, reason = risk_analysis(extension, detected_type)

    print("\n--- File Type Analysis Report ---")
    print(f"File Name     : {os.path.basename(file_path)}")
    print(f"Extension     : {extension}")

    if matched_magic:
        formatted_magic = " ".join(
            matched_magic[i:i+2] for i in range(0, len(matched_magic), 2)
        )
        print(f"Magic Number  : {formatted_magic} (offset {offset})")
    elif "TEXT" in detected_type or detected_type.startswith("SCRIPT FILE"):
        print("Magic Number  : Text-based detection (heuristic)")
    else:
        print("Magic Number  : Not found")

    print(f"Detected Type : {detected_type}")
    print(f"Risk Level    : {risk}")
    print(f"Reason        : {reason}")
    print("--------------------------------\n")


# -------------------------------
# Entry point
# -------------------------------
if __name__ == "__main__":
    main()
