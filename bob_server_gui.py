# bob_server_gui.py
import sys, socket, threading, json, base64, os, tempfile
from PyQt6.QtWidgets import *
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QUrl, Qt
from key_encryption import encrypt_message, decrypt_message


class BobServer(QMainWindow):
    def __init__(self):
        # Sets up the main window 
        super().__init__()
        self.setWindowTitle("Bob (Server)")
        self.resize(500, 500)

        # Create the overall layout for the app, will add widgets to this layout
        layout = QVBoxLayout()

        # The "recieved_box" will contain all of message history between Bob and Alice
        self.received_box = QTextEdit()
        self.received_box.setReadOnly(True) # Can only read this section, don't want to be able to modify chat history
        layout.addWidget(QLabel("Received (decrypted):")) 
        layout.addWidget(self.received_box) 

        # Remeber what the last ciphertext was for decryption
        self.last_ciphertext = None
        
        # Adding the decrypt button to the layout
        self.decrypt_button = QPushButton("Decrypt")
        layout.addWidget(self.decrypt_button)
        self.decrypt_button.clicked.connect(self.try_decryption) # connect it to the try_decryption function

        # Creating the area where the shared passphrase is input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password) # Hides the password characters
        layout.addWidget(QLabel("Enter password for Decryption:"))
        layout.addWidget(self.password_input)

        # Checkbox to swithc between the 56 and 128 bit keys (DES/AES)
        self.checkbox_aes = QCheckBox("Use AES-128 (Uncheck for DES-56)")
        self.checkbox_aes.setChecked(True) # Default is 128 AES
        layout.addWidget(self.checkbox_aes)

        # Create dropdown menu for send options
        self.send_option_combo = QComboBox()
        self.send_option_combo.addItem("Send Text")
        self.send_option_combo.addItem("Send File")
        self.send_option_combo.addItem("Send Voice")
        self.send_option_combo.addItem("Send Picture")
        layout.addWidget(self.send_option_combo)

        # Create stacked widget to switch between interfaces
        self.send_stack = QStackedWidget()

        # Option 1: Text sending interface
        text_page = QWidget()
        text_layout = QHBoxLayout()
        self.text_send = QLineEdit()
        self.btn_send_text = QPushButton("Send to Alice")
        text_layout.addWidget(self.text_send)
        text_layout.addWidget(self.btn_send_text)
        text_page.setLayout(text_layout)
        self.send_stack.addWidget(text_page)

        # Option 2: File sending interface
        file_page = QWidget()
        file_layout = QVBoxLayout()
        self.btn_send_file = QPushButton("Select File to Send")
        file_layout.addWidget(self.btn_send_file)
        file_page.setLayout(file_layout)
        self.send_stack.addWidget(file_page)

        # Option 3: Voice sending
        voice_page = QWidget()
        voice_layout = QVBoxLayout()
        self.btn_send_voice = QPushButton("Select Voice (.wav) File to Send")
        voice_layout.addWidget(self.btn_send_voice)
        voice_page.setLayout(voice_layout)
        self.send_stack.addWidget(voice_page)

        # Option 4: Picture sending
        picture_page = QWidget()
        picture_layout = QVBoxLayout()
        self.btn_send_picture = QPushButton("Select Picture (.png, .jpeg) File to Send")
        picture_layout.addWidget(self.btn_send_picture)
        picture_page.setLayout(picture_layout)
        self.send_stack.addWidget(picture_page)

        layout.addWidget(self.send_stack) # add all the pages to the main layout

        # Update button connections with their corresponding functions
        self.btn_send_text.clicked.connect(self.send_message)
        self.btn_send_file.clicked.connect(self.send_file)
        self.btn_send_voice.clicked.connect(self.send_voice)
        self.btn_send_picture.clicked.connect(self.send_picture)
        
        # Connect dropdown to switch views
        self.send_option_combo.currentIndexChanged.connect(self.send_stack.setCurrentIndex)

        # Create the main container to put our layout in
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Networking, creating Bob as the server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("localhost", 9000)) # bind bob to port 9000
        self.server_socket.listen(1) # listen for Alice
        threading.Thread(target=self.wait_for_connection, daemon=True).start() # wait for incoming connection on the thread

        self.client_conn = None # variable to store active client connections
        
    # Function to handle connections to the server
    def wait_for_connection(self):
        self.received_box.append("Listening on: localhost:9000")
        self.client_conn, addr = self.server_socket.accept() # accepts incoming connections but blocks until one is available
        self.received_box.append(f"Connected with: {addr[0]}:{addr[1]}")
        threading.Thread(target=self.receive_data, daemon=True).start() # start thread so Bob can recieve data from Alice

    # Function for sending encrypted text communication
    def send_message(self):
        if self.client_conn:
            password = self.password_input.text().encode() # encode the password from the passphrase input area
            if not password:
                self.received_box.append("No password entered.")
                return
            msg = self.text_send.text() # msg is set to the text in the text_send box (to send)
            aes_mode = self.checkbox_aes.isChecked() # check if it will be 128 bit key or 56 bit key
            # Encrypts the message using the function from the key_encryption.py file
            cipher = encrypt_message(msg, password, aes_mode=aes_mode) 
            # Sends the client (Alice) the full JSON dump from the key_encryption.py
            self.client_conn.send(cipher.encode())
            self.received_box.append(f"You → Alice: {msg}")
    
    # Function for sending encrypted files
    def send_file(self):
        # Opens the File Explorer to select a file to send
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not filepath:
            return
        # Reads the file 
        with open(filepath, "rb") as f:
            data = f.read()

        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath) # Extract the file name

        content_str = base64.b64encode(data).decode() # Create a string that represents the content in the file
        payload = json.loads(encrypt_message(content_str, password, aes_mode)) # pass this string as the "message" into the encryption function
        payload["type"] = "file" # set the type in the JSON dump to "file"
        payload["filename"] = filename # Add the filename as well

        # Send payload
        json_to_send = json.dumps(payload)
        self.client_conn.send(json_to_send.encode()) # send Alice the encrypted payload
        self.received_box.append(f"File sent: {filename}")  # Display confirmation
    
    # Function for sending encrypted voice files
    def send_voice(self):
        # Open File Explorer, filter to .wav files
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Voice (.wav) File to Send", filter="WAV files (*.wav)")
        if not filepath:
            return
        with open(filepath, "rb") as f:
            data = f.read()

        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath)

        # Same setup as for file communcation, but we set the type to "voice" and filter to .wav files
        content_str = base64.b64encode(data).decode()
        payload = json.loads(encrypt_message(content_str, password, aes_mode)) # pass the base64 string of the file to be encrypted
        payload["type"] = "voice"
        payload["filename"] = filename

        json_to_send = json.dumps(payload)
        self.client_conn.send(json_to_send.encode())
        self.received_box.append(f"Voice message sent: {filename}")

    # Function for sending encrypted picture files
    def send_picture(self):
        # Open File Explorer, filtered to picture type files
        filepath, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Picture File to Send", 
            filter="Image files (*.png *.jpg *.jpeg *.bmp)"
        )
        if not filepath:
            return

        with open(filepath, "rb") as f:
            data = f.read()

        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath)

        # As with the previous two functions, still reading the base64 data of the file and passing that through as our encrypted payload
        content_str = base64.b64encode(data).decode()
        payload = json.loads(encrypt_message(content_str, password, aes_mode))
        payload["type"] = "picture"
        payload["filename"] = filename

        json_to_send = json.dumps(payload)
        self.client_conn.send(json_to_send.encode())
        self.received_box.append(f"Picture sent: {filename}")
    
    # Function for recieving data
    def receive_data(self):
        buffer = b'' # Buffer for handling incomplete messages
        while True:
            try:
                # Recieve data from the client (Alice)
                data = self.client_conn.recv(4096)
                if not data: # if no connection then break
                    break
                buffer += data # add the buffer to the data
                
                # Try to parse complete JSON from buffer
                while buffer:
                    try:
                        message = buffer.decode() # attempt to decode the buffer
                        json.loads(message)  # Validate JSON
                        # Complete message received
                        self.last_ciphertext = message # Store the complete message for decryption
                        buffer = b''  # Clear buffer
                        
                        # Parsing the recieved data
                        cipher_obj = json.loads(message)
                        msg_type = cipher_obj.get("type", "text") # determine the type of message ("voice", "text", "picture", "file")
                        actualCipher = cipher_obj.get("ciphertext", "???") # set "actualCipher" to the encrypted payload string
                        filename = cipher_obj.get("filename", "received_file") # in case we want to give the name of the file

                        if msg_type == "text":
                            self.received_box.append(f"Encrypted: {actualCipher}")
                        elif msg_type == "file":
                            self.received_box.append(f"Encrypted file received: {actualCipher} (click 'Decrypt' to access)")
                        elif msg_type == "voice":
                            self.received_box.append(f"Encrypted voice file received: {actualCipher} (click 'Decrypt' to play)")
                        elif msg_type == "picture":
                            self.received_box.append(f"Encrypted picture file received: {actualCipher} (click 'Decrypt' to show)")
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Incomplete message, wait for more data
                        break
            except Exception as e:
                self.received_box.append(f"Error: {e}")
                break
    
    # Decryption function
    def try_decryption(self):
        # If we have not sent anything and still try to decrypt:
        if not self.last_ciphertext:
            self.received_box.append("No message to decrypt.")
            return
        
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()

        # Use the decrypt_message function from key_encryption.py
        decrypted = decrypt_message(self.last_ciphertext, password, aes_mode=aes_mode)

        # Determine the original message, similar to recieve data where we want to determine the type
        cipher_obj = json.loads(self.last_ciphertext)
        msg_type = cipher_obj.get("type", "text") # lets us know what to output if found to be decrypted
        filename = cipher_obj.get("filename", "received_file")

        # MODE_MISMATCH is from key_encryption.py, lets us know if the sender uses AES or DES and to swap accordingly
        if decrypted == "__MODE_MISMATCH__":
            self.received_box.append("❌ Mode mismatch! Sender used AES/DES but you selected the opposite.\n")
        elif decrypted is None:
            self.received_box.append("❌ Decryption failed: Wrong password or corrupted data.\n")
        elif msg_type == "file":
            self.try_save_file(decrypted, filename) # tries to save the file shared
        elif msg_type == "voice":
            try:
                # Decode and save the voice file as a temp file to play
                decoded = base64.b64decode(decrypted)
                tmp_dir = tempfile.gettempdir()
                tmp_path = os.path.join(tmp_dir, filename)
                with open(tmp_path, "wb") as f:
                    f.write(decoded)

                self.received_box.append(f"Voice saved to: {tmp_path}")

                # Sets up audio player and play the message
                self.audio_output = QAudioOutput()
                self.media_player = QMediaPlayer()
                self.media_player.setAudioOutput(self.audio_output)
                self.media_player.setSource(QUrl.fromLocalFile(tmp_path))
                self.media_player.play()

                self.received_box.append("Playing voice message...\n")
            except Exception as e:
                self.received_box.append(f"❌ Error playing voice message: {str(e)}")
        elif msg_type == "picture":
            self.display_picture(decrypted, filename) # Displays the image
        else:
            self.received_box.append(f"Decrypted: {decrypted}\n") # Shows decrypted message

    # Function for saving a file transferred (after decryption)
    def try_save_file(self, decrypted_str, filename):
        try:
            decoded_data = base64.b64decode(decrypted_str) # decode the base64 string
            # Open the save dialog
            dest, _ = QFileDialog.getSaveFileName(
                self, 
                "Save received file", 
                filename
            )
            if dest:
                # Save file logic
                with open(dest, "wb") as f:
                    f.write(decoded_data)
                self.received_box.append(f"File saved: {dest}\n")
        except Exception as e:
            self.received_box.append(f"❌ Error saving file: {str(e)}")

    # Function for displaying decrypted pictures
    def display_picture(self, decrypted_str, filename):
        try:
            decoded = base64.b64decode(decrypted_str)
            
            # Create a dialog to display the image
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Received Image: {filename}")
            layout = QVBoxLayout()
            
            # Create image label
            image_label = QLabel()
            pixmap = QPixmap()
            pixmap.loadFromData(decoded)
            
            # Scale if too large
            if pixmap.width() > 800 or pixmap.height() > 600:
                pixmap = pixmap.scaled(800, 600, Qt.AspectRatioMode.KeepAspectRatio)
            
            image_label.setPixmap(pixmap)
            layout.addWidget(image_label)
            
            # Add save button
            btn_save = QPushButton("Save Image")
            btn_save.clicked.connect(lambda: self.save_image(decoded, filename)) # connects to the save_image function
            layout.addWidget(btn_save)
            
            dialog.setLayout(layout)
            dialog.exec()
            
            self.received_box.append(f"Image displayed: {filename}")
        except Exception as e:
            self.received_box.append(f"❌ Error displaying image: {str(e)}")

    # Function for saving the image 
    def save_image(self, image_data, filename):
        dest, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Image", 
            filename
        )
        if dest:
            with open(dest, "wb") as f:
                f.write(image_data)
            self.received_box.append(f"Image saved to: {dest}")


# Starts up the application on run
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = BobServer()
    win.show()
    sys.exit(app.exec())

