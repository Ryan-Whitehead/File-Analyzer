# 🔍 Magic File Analyzer

A Python application that analyzes file signatures, detects MIME types, and identifies potential security risks by comparing file extensions with actual content.

## ✨ Features

- **File Signature Analysis**: Detects actual file type using magic numbers (not just extensions)
- **MIME Type Detection**: Identifies true MIME types via python-magic library
- **Security Verification**: Flags mismatched extensions that could indicate malware
- **Dual Interface**: Command Line Interface (CLI) or Graphical User Interface (GUI)
- **Cross-Platform**: Works on Linux, Windows, and macOS

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)

## 🚀 Quick Installation

### Linux/macOS:

```bash
pip install python-magic
sudo apt-get install libmagic1  # Ubuntu/Debian
# or: brew install libmagic      # macOS

### Windows
pip install python-magic-bin

##Normal File:
==================================================
Magic Number Analysis:
==================================================
File extension: .txt
File command output: ASCII text
MIME type: text/plain

--------------------------------------------------
EXTENSION VERIFICATION:
✅ Extension matches file content
==================================================

##Suspicious File
==================================================
Magic Number Analysis:
==================================================
File extension: .pdf
File command output: ELF 64-bit executable
MIME type: application/x-executable

--------------------------------------------------
EXTENSION VERIFICATION:
⚠️  WARNING: File extension does NOT match actual content!
   Extension '.pdf' suggests PDF document,
   but file actually contains: ELF 64-bit executable
==================================================

## Running the Application

###CLI Mode:

python3 file_analyzer.py
# Enter file path when prompted

###GUI Mode
# Make executable (Linux/macOS)
chmod +x gui_analyzer.py

# Run
python3 gui_analyzer.py
# or double-click the file

###Project Structure
file-analyzer/
├── file_analyzer.py    # CLI version
├── gui_file_analyzer.py     # GUI version
└── README.md          # This file
```
