# 🔐 Encrypted P2P Chat – Alice & Bob

A secure peer-to-peer messaging application featuring manual decryption with user-supplied passwords and selectable encryption strength (AES-128 or DES-56). Built with Python and PyQt6, this GUI-based app enables encrypted communication between two clients without transmitting raw plaintext.

---

## 🛠 Features

- ✅ Encrypted messaging using **AES-128** or **DES-56**
- 🔑 Users enter a shared password to derive encryption keys securely
- 🔒 Messages are transmitted in encrypted form only
- 🧠 Decryption is manual — users must input the correct password and key mode to unlock messages
- 🧰 Key derivation using **PBKDF2** with a random salt per message
- 📦 Uses **PKCS7 padding** for both AES and DES block sizes
- 🧪 Robust against mode mismatches and incorrect passwords (fails gracefully)

---
## 🚀 Setup Instructions

### Requirements

- Python 3.10+
- Dependencies:
  - `PyQt6`
  - `cryptography`
  - `pycryptodome`

### Install Dependencies

```bash
pip install PyQt6 cryptography pycryptodome
```

---
## ▶️ How to Use

### 1. Run Bob (server)

```bash
python bob_server_gui.py
```

- Bob listens on port 9000.
- Choose encryption type (AES or DES) and input the shared password.

### 2. Run Alice (client)

```bash
python alice_client_gui.py
```

- Connects to Bob on localhost:9000.
- Use the same password and encryption type to communicate successfully.

### 3. Send & Receive Messages

- Type your message and click **Send**.
- The encrypted ciphertext will appear in both GUIs.
- To decrypt, input the correct password, choose the correct cipher, and click **Decrypt Last Message**.

---
## 🧑‍💻 Author

**Trevor Bean - University of Oklahoma**  
CS-4173 Project – Secure Messaging System  
2025

