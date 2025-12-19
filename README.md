# Crypter Pro - Advanced Secure File Encryption 🔐

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: AES-GCM](https://img.shields.io/badge/Security-AES--256--GCM-green)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

A professional-grade encryption tool for Windows, featuring password-based security, folder processing, and secure file shredding.

## 🌟 Key Features

*   **🔑 Secure Key Derivation:** Uses PBKDF2 with SHA-256 and 100,000 iterations to derive a 256-bit key from your password, protecting against brute-force attacks.
*   **🛡️ Authenticated Encryption:** Employs **AES-256-GCM** (Galois/Counter Mode) to ensure both confidentiality and integrity. The app detects if an encrypted file has been tampered with.
*   **📂 recursive Folder Support:** Encrypt or Decrypt entire directories while maintaining folder structures.
*   **🖱️ Drag & Drop Interface:** Integrated with `tkinterdnd2` for a seamless Windows Explorer-like experience.
*   **🗑️ Secure File Shredding:** Implements a multi-pass secure deletion algorithm to wipe original files after encryption, preventing forensic recovery.
*   **⚡ Asynchronous Processing:** Built with `threading` to keep the UI responsive during intensive cryptographic operations.

## 🛠️ Technical Stack

- **Language:** Python 3.11+
- **GUI Framework:** Tkinter / CustomTkinter
- **Cryptography:** `pycryptodome`
- **Build Tool:** PyInstaller

## 🚀 Installation & Setup

1.  **Clone & Navigate:**
    ```bash
    git clone https://github.com/SBTabanar/CrypterPro.git
    cd CrypterPro
    ```

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run Application:**
    ```bash
    python app.py
    ```

## 📦 Distribution

To build a standalone `.exe`:
```bash
pyinstaller --noconfirm --onefile --windowed --name "CrypterPro" --add-data "venv/Lib/site-packages/tkinterdnd2;tkinterdnd2" app.py
```

## ⚠️ Critical Security Notes

- **Password Responsibility:** Encryption keys are derived solely from your password. If lost, data recovery is mathematically impossible.
- **Integrity Checks:** The GCM authentication tag ensures that if even a single bit of the file is changed, decryption will fail, alerting you to potential corruption or tampering.

## 🧑‍💻 Author

**Sergei Benjamin Tabanar**
*BS IT Student | Major in Network & Information Security*
[LinkedIn](https://linkedin.com) • [Portfolio](https://sergeibenjamin.com)