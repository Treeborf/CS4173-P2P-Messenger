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
  - Decryption with shared passphrase
  - Per-message random salt generation
  - PBKDF2 key derivation 
  - Mode verification to prevent cipher mismatch
- **User Experience**:
  - Media playback for voice messages
  - Image preview with save option
  - Automatic file saving dialog

---

## 🚀 Setup Instructions

### Requirements
- Up-to-date Windows or Linux Distro
- Python 3.10+ (latest build recommended)
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

### 1.1. Open Terminal 

- Ensure that you are in the folder containing the .py files before attempting to run these commands ('cd' for both Linux and Windows)
- (Located within 'Final_Project/Source_Files_and_Libraries' for CS4173 Professor/TAs)

### 1.2. Run Bob (server)

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

### 3.1 Firewall Configuration (If Connection not Working)
- If connection fails:
  - Temporarily disable firewalls during testing
  - On Windows: Allow Python through Windows Defender Firewall
  - On macOS/Linux: Ensure port 9000 is open

### 4. Sending Messages

- Choose content type from dropdown:
  - **Text**: Type message --> "Send to (Bob/Alice)"
  - **File**: Select any file 
  - **Voice**: Choose any .wav file
  - **Image**: Select any image (.png, .jpeg, etc.)
- Recipient clicks **Decrypt** to view/save content
---

## 🐛 Troubleshooting

### ❌ "ModuleNotFoundError" during startup
Run: `pip install --upgrade PyQt6 cryptography pycryptodome`

### ❌ Connection Refused Errors
1. Ensure Bob is running before Alice
2. Verify both are using same machine (localhost)
3. Check no other program is using port 9000:
   ```bash
   # Linux/macOS
   lsof -i :9000
   
   # Windows
   netstat -ano | findstr :9000
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


