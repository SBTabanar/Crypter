# Crypter Pro - Advanced Secure File Encryption

A professional-grade encryption tool for Windows, featuring password-based security, folder processing, and secure file shredding.

## 🌟 Pro Features

*   **🔑 Password-Based Encryption:** No more key files! Uses PBKDF2 (SHA-256) to derive secure keys from your password.
*   **📂 Folder Support:** Encrypt or Decrypt entire directories recursively with one click.
*   **🖱️ Drag & Drop:** seamless integration with Windows Explorer. Just drop your files/folders into the app.
*   **🗑️ Secure Shredding:** Option to securely wipe original files after encryption to prevent recovery.
*   **⚡ Multi-threaded:** UI stays responsive during large operations.

## 🛠️ Installation

1.  **Prerequisites:** Python 3.x
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Usage Guide

1.  **Select Target:** Drag and drop a file or folder onto the "Drop Zone", or click it to browse.
2.  **Enter Password:** Type a strong password. You must use the **same password** to decrypt later.
3.  **Choose Action:**
    *   **ENCRYPT:** Locks the file(s). (Optional: Check "Securely Shred" to delete originals).
    *   **DECRYPT:** Unlocks the file(s).
4.  **Wait:** Watch the logs and progress bar.

## 📦 Building Executable (.exe)

To create a standalone file for distribution:

```bash
pyinstaller --noconfirm --onefile --windowed --name "CrypterPro" --add-data "venv/Lib/site-packages/tkinterdnd2;tkinterdnd2" app.py
```
*(Note: You may need to adjust the tkinterdnd2 path depending on your python install location)*

## ⚠️ Security Notice

*   **Remember your password!** There is NO "Forgot Password" feature. If you forget it, your data is lost forever.
*   **Shredding is permanent.** Securely deleted files cannot be recovered.

## 🧑‍💻 Developer

*   Sergei Benjamin Tabanar