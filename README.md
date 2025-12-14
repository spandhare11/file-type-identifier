# 🔐 File Type Identifier using Magic Numbers

A Python-based **security-focused CLI tool** that detects the **real file type**
by analyzing **file content**, not filenames or MIME types.

The tool uses:
- Magic numbers (file signatures)
- Offset-based detection (e.g., TAR)
- ASCII / UTF-8 text heuristics
- Shebang (executable script) detection

This approach helps prevent **file masquerading attacks**, which are a common root cause of
**unrestricted file upload vulnerabilities** in real-world applications.

---

## 🎯 Why This Tool Exists

Many applications validate uploaded files using:
- File extensions (`.jpg`, `.png`)
- Browser-supplied MIME types
- Simple allow/deny lists

These checks are **trivial to bypass**.

### 🔴 Real-world attack examples
- `shell.php.png` → Remote Code Execution
- `cmd.py.jpg` → Script execution
- `firmware.tar.png` → Archive extraction abuse
- `backdoor.sh.gif` → CI/CD pipeline compromise

This tool solves the problem by **never trusting the filename** and instead validating
the **actual file structure**.

---

## 🚀 Features

- ✅ Magic number detection (PNG, JPEG, PDF, ELF, EXE, ZIP, etc.)
- ✅ Offset-aware signatures (TAR detection at byte 257)
- ✅ ASCII / UTF-8 text detection (heuristic-based)
- ✅ Shebang detection (`#!/bin/bash`, `#!/usr/bin/python`, etc.)
- ✅ Context-aware risk classification
- ✅ No external dependencies
- ✅ Works fully offline

---

## 🧪 Example Usage

```bash
python3 fileidentifier.py shell.php.png

---


## ⚠️ Note:
magic_numbers.json is required for the tool to work and is included in this repository.
Do not delete or move this file

