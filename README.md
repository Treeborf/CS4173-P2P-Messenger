# 🔐 Secure Instant Peer-to-Peer (P2P) Messenger

A secure peer-to-peer messaging application featuring **manual decryption** with shared passphrases and choice of encryption strength (AES-128 or DES-56). Built with Python and PyQt6, this GUI-based app showcases encrypted communication between a client and a server without transmitting raw plaintext.

---

## 🛠 Features

- **Dual Encryption Support**:
  - **AES-128** (recommended for security)
  - **DES-56** (for compatibility/testing)
- **Multi-Content Support**:
  - Encrypted text messaging
  - Secure file transfers
  - Voice message transmission (.wav)
  - Image sharing with in-app viewing
- **Security Features**:
  - Manual decryption with shared passphrase
  - Per-message random salt generation
  - PBKDF2 key derivation (100,000 iterations)
  - Mode verification to prevent cipher mismatch
- **User Experience**:
  - In-app media playback for voice messages
  - Image preview with save option
  - Visual indicators for different content types
  - Automatic file saving dialog

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

- Bob listens on port 9000
- Choose encryption type (AES or DES) and input the shared password

### 2. Run Alice (client)

```bash
python alice_client_gui.py
```

- Connects to Bob on localhost:9000
- Use the same password and encryption type to communicate successfully

### 3. Establish a Secure Connection

- Both parties enter shared passphrase
- Select a matching encryption mode (either AES or DES)
- Confirm Connection status in the chat window

### 4. Sending Messages

- Choose content type from dropdown:
  - **Text**: Type message --> "Send to (Bob/Alice)"
  - **File**: Select any file 
  - **Voice**: Choose any .wav file
  - **Image**: Select any image (.png, .jpeg, etc.)
- Recipient clicks **Decrypt** to view/save content
---

## ❓FAQ

### ❌ What happens if Alice and Bob use different passwords?
The message cannot be decrypted — the app displays a decryption error.

### ❌ What if Alice uses AES and Bob selects DES?
Decryption fails with a "mode mismatch" warning. The encryption algorithm is embedded in the message metadata.

---
## 🧑‍💻 Author

**Trevor Bean - University of Oklahoma**  
CS-4173 Project – Secure Messaging System  
2025

