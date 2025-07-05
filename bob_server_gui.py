# bob_server_gui.py
import sys, socket, threading, json
from PyQt6.QtWidgets import *
from key_encryption import encrypt_message, decrypt_message

class BobServer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bob (Server)")
        self.resize(400, 300)

        layout = QVBoxLayout()
        self.received_box = QTextEdit()
        self.received_box.setReadOnly(True)
        layout.addWidget(QLabel("Received (decrypted):"))
        layout.addWidget(self.received_box)

        self.last_ciphertext = None
        
        self.decrypt_button = QPushButton("Decrypt")
        layout.addWidget(self.decrypt_button)
        self.decrypt_button.clicked.connect(self.try_decryption)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Enter password for Decryption:"))
        layout.addWidget(self.password_input)

        self.checkbox_aes = QCheckBox("Use AES-128 (Uncheck for DES-56)")
        self.checkbox_aes.setChecked(True) # Default is 128 AES
        layout.addWidget(self.checkbox_aes)

        self.text_send = QLineEdit()
        self.btn_send = QPushButton("Send to Alice")
        layout.addWidget(self.text_send)
        layout.addWidget(self.btn_send)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("localhost", 9000))
        self.server_socket.listen(1)
        threading.Thread(target=self.wait_for_connection, daemon=True).start()

        self.client_conn = None
        self.btn_send.clicked.connect(self.send_message)
        
    def wait_for_connection(self):
        self.received_box.append("Listening on: localhost:9000")
        self.client_conn, addr = self.server_socket.accept()
        self.received_box.append(f"Connected with: {addr[0]}:{addr[1]}")
        threading.Thread(target=self.receive_data, daemon=True).start()

    def send_message(self):
        if self.client_conn:
            password = self.password_input.text().encode()
            if not password:
                self.received_box.append("No password entered.")
                return
            msg = self.text_send.text()
            aes_mode = self.checkbox_aes.isChecked()
            cipher = encrypt_message(msg, password, aes_mode=aes_mode)
            self.client_conn.send(cipher.encode())
            self.received_box.append(f"You → Alice: {cipher}")
    
    def receive_data(self):
        while True:
            data = self.client_conn.recv(1024)
            if not data:
                break
            try:
                message = data.decode()
                self.last_ciphertext = message
                cipher_obj = json.loads(message)
                actualCipher = cipher_obj.get("ciphertext", "???")
                self.received_box.append(f"Encrypted: {actualCipher}")
            except Exception as e:
                self.received_box.append(f"Error: {e}")

    def try_decryption(self):
        if not self.last_ciphertext:
            self.received_box.append("No message to decrypt.")
            return
        
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()

        decrypted = decrypt_message(self.last_ciphertext, password, aes_mode=aes_mode)

        if decrypted == "__MODE_MISMATCH__":
                self.received_box.append("❌ Mode mismatch! Sender used AES/DES but you selected the opposite.\n")
        elif decrypted is None:
                self.received_box.append("❌ Decryption failed: Wrong password or corrupted data.\n")
        else:
                self.received_box.append(f"Plain: {decrypted}\n")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = BobServer()
    win.show()
    sys.exit(app.exec())
