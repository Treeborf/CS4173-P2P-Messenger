# alice_client_gui.py
import sys, socket, threading, json, base64, os, tempfile
from PyQt6.QtWidgets import *
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QUrl, Qt
from key_encryption import encrypt_message, decrypt_message

class AliceClient(QMainWindow):
    def __init__(self):
        # Sets up the main window 
        super().__init__()
        self.setWindowTitle("Alice (Client)")
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
        self.btn_send_text = QPushButton("Send to Bob")
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

        # Sets up the networking using the socket library
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("localhost", 9000)) # connects to the localhost port (Bob)
        local_ip, local_port = self.client_socket.getsockname() 
        remote_ip, remote_port = self.client_socket.getpeername()

        # Lists where Alice is connected from, and who she is connecting to (Bob the server)
        self.received_box.append(f"Connected from: {local_port}:{local_port}") 
        self.received_box.append(f"Connected to: {remote_ip}:{remote_port}")

        threading.Thread(target=self.receive_data, daemon=True).start() # start thread for connections

    # Function for sending encrypted messages
    def send_message(self):
        password = self.password_input.text().encode() # read the password text from the password_input box
        if not password:
            self.received_box.append("No password entered.")
            return
        msg = self.text_send.text() # read the message text from the text_send box
        aes_mode = self.checkbox_aes.isChecked() # check if it is AES/DES
        # Encrypt using the encryption function from key_encryption.py
        cipher = encrypt_message(msg, password, aes_mode=aes_mode) 
        # Send the server (Bob) the encrypt_message output (JSON dump)
        self.client_socket.send(cipher.encode())
        self.received_box.append(f"You → Bob: {msg}")
    
    # Function for sending encrypted files
    def send_file(self):
        # Opens File Explorer
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not filepath:
            return
        # Reads the file and puts it into the data variable
        with open(filepath, "rb") as f:
            data = f.read()

        # Read in all the important information for encryption
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath)

        content_str = base64.b64encode(data).decode() # Construct a string using base64 serialization that represents the file contents
        payload = json.loads(encrypt_message(content_str, password, aes_mode)) # pass the content_str as the "message" into the encryption function
        payload["type"] = "file" # Set type to "file"
        payload["filename"] = filename # Save filename 

        # Send encrypted payload
        json_to_send = json.dumps(payload)
        self.client_socket.send(json_to_send.encode())
        self.received_box.append(f"📎 File sent: {filename}")

    # Function for sending encrypted voice files
    def send_voice(self):\
        # Open File Explorer, filtered for .wav files
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Voice (.wav) File to Send", filter="WAV files (*.wav)")
        if not filepath:
            return
        with open(filepath, "rb") as f:
            data = f.read()

        # Gather important information for the encryption function
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath)

        content_str = base64.b64encode(data).decode() # convert the contents of the voice file to a string
        payload = json.loads(encrypt_message(content_str, password, aes_mode)) # encrypt the voice file payload
        payload["type"] = "voice" # set type to "voice"
        payload["filename"] = filename # save filename

        json_to_send = json.dumps(payload)
        self.client_socket.send(json_to_send.encode()) # send Bob the payload 
        self.received_box.append(f"🎤 Voice message sent: {filename}")

    # Function for sending encrypted images
    def send_picture(self):
        # Open File Explorer, filter to picture file types
        filepath, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Picture File to Send", 
            filter="Image files (*.png *.jpg *.jpeg *.bmp)"
        )
        if not filepath:
            return
        with open(filepath, "rb") as f:
            data = f.read()

        # Gather info for encryption function
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()
        filename = os.path.basename(filepath)

        content_str = base64.b64encode(data).decode() # convert the picture contents to a string
        payload = json.loads(encrypt_message(content_str, password, aes_mode)) # use the converted string in the encryption function
        payload["type"] = "picture" # set type to "picture"
        payload["filename"] = filename # save filename

        # Send the encrypted payload (JSON)
        json_to_send = json.dumps(payload)
        self.client_socket.send(json_to_send.encode()) 
        self.received_box.append(f"🖼️ Picture sent: {filename}")

    # Function for recieving data
    def receive_data(self):
        buffer = b'' # buffer for incomplete messages, set as a bytes object
        while True:
            try:
                data = self.client_socket.recv(4096)  # Alice uses client_socket, recieves data from Bob
                if not data:
                    break
                buffer += data # add the buffer to the data
                
                # Try to parse complete JSON from buffer
                while buffer:
                    try:
                        message = buffer.decode() # try to decode
                        json.loads(message)  # Validate JSON
                        # Complete message received
                        self.last_ciphertext = message # store for decryption
                        buffer = b''  # Clear buffer
                        
                        # parse the message recieved
                        cipher_obj = json.loads(message)
                        msg_type = cipher_obj.get("type", "text")
                        actualCipher = cipher_obj.get("ciphertext", "???")
                        filename = cipher_obj.get("filename", "received_file")

                        # Depending on the type of message recieved, ouput recieved messages in the chat history
                        if msg_type == "text":
                            self.received_box.append(f"Encrypted: {actualCipher}")
                        elif msg_type == "file":
                            self.received_box.append(f"📥 Encrypted file received: {actualCipher} (click 'Decrypt' to access)")
                        elif msg_type == "voice":
                            self.received_box.append(f"🎤 Encrypted voice file received: {actualCipher} (click 'Decrypt' to play)")
                        elif msg_type == "picture":
                            self.received_box.append(f"🖼️ Encrypted picture file received: {actualCipher} (click 'Decrypt' to show)")
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Incomplete message, wait for more data
                        break
            except Exception as e:
                self.received_box.append(f"Error: {e}")
                break

    # Function for decrypting recieved data
    def try_decryption(self):
        # If no ciphertext sent though, return
        if not self.last_ciphertext:
            self.received_box.append("No message to decrypt.")
            return
        
        # Check the password and AES/DES boxes
        password = self.password_input.text().encode()
        aes_mode = self.checkbox_aes.isChecked()

        # Attempt decryption using the decrypt_message function from key_encryption.py
        decrypted = decrypt_message(self.last_ciphertext, password, aes_mode=aes_mode)

        # Load the JSON of the original message, determine the message type and file name
        cipher_obj = json.loads(self.last_ciphertext)
        msg_type = cipher_obj.get("type", "text")
        filename = cipher_obj.get("filename", "received_file")

        # Check if the password is wrong, if the AES/DES mode is incorrect, or what type of transfer it is
        if decrypted == "__MODE_MISMATCH__":
            self.received_box.append("❌ Mode mismatch! Sender used AES/DES but you selected the opposite.\n")
        elif decrypted is None:
            self.received_box.append("❌ Decryption failed: Wrong password or corrupted data.\n")
        elif msg_type == "file":
            self.try_save_file(decrypted, filename) # Save the decrypted file
        elif msg_type == "voice":
            try:
                decoded = base64.b64decode(decrypted) # decode the voice file string
                tmp_dir = tempfile.gettempdir() # create a temp file to play from
                tmp_path = os.path.join(tmp_dir, filename)
                with open(tmp_path, "wb") as f:
                    f.write(decoded)

                self.received_box.append(f"✅ Voice saved to: {tmp_path}")

                # Set up player and play the decrypted voice message
                self.audio_output = QAudioOutput()
                self.media_player = QMediaPlayer()
                self.media_player.setAudioOutput(self.audio_output)
                self.media_player.setSource(QUrl.fromLocalFile(tmp_path))
                self.media_player.play()

                self.received_box.append("🔊 Playing voice message...\n")
            except Exception as e:
                self.received_box.append(f"❌ Error playing voice message: {str(e)}")
        elif msg_type == "picture":
            self.display_picture(decrypted, filename) # show the file after decryption
        else:
            self.received_box.append(f"✅ Decrypted: {decrypted}\n") # display the decrypted message (if text communcation)
    
    # Function for saving a file from a file transfer
    def try_save_file(self, decrypted_str, filename):
        try:
            decoded_data = base64.b64decode(decrypted_str) # read in the decoded file string
            # Open File Explorer to save
            dest, _ = QFileDialog.getSaveFileName(
                self, 
                "Save received file", 
                filename
            )
            if dest:
                with open(dest, "wb") as f:
                    f.write(decoded_data) # write a new file with the decoded data
                self.received_box.append(f"✅ File saved: {dest}\n")
        except Exception as e:
            self.received_box.append(f"❌ Error saving file: {str(e)}")

    # Function for displaying a decrypted picture
    def display_picture(self, decrypted_str, filename):
        try:
            decoded = base64.b64decode(decrypted_str) # read in the decrypted string from the original picture
            
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
            btn_save.clicked.connect(lambda: self.save_image(decoded, filename)) # call the save_image function to save the decrypted picture
            layout.addWidget(btn_save)
            
            dialog.setLayout(layout)
            dialog.exec()
            
            self.received_box.append(f"✅ Image displayed: {filename}") # display the name of the file and the picture
        except Exception as e:
            self.received_box.append(f"❌ Error displaying image: {str(e)}")

    # Function for saving an image
    def save_image(self, image_data, filename):
        dest, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Image", 
            filename
        )
        if dest:
            with open(dest, "wb") as f:
                f.write(image_data) # writes the image data (decoded picture data) into a file to save
            self.received_box.append(f"💾 Image saved to: {dest}")

# Starts up the application on execution
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AliceClient()
    win.show()
    sys.exit(app.exec())

