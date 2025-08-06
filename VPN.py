import sys
import socket
import threading
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QTextEdit, QLineEdit,
QLabel, QVBoxLayout, QHBoxLayout
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VPNGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VPN")
        self.setGeometry(300, 300, 600, 400)

        # AES Key
        self.KEY = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.KEY)

        # GUI elements
        self.ip_label = QLabel("Server IP:")
        self.ip_input = QLineEdit("127.0.0.1")

        self.port_label = QLabel("Port:")
        self.port_input = QLineEdit("9999")

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type your message here...")
        self.msg_input.setEnabled(False)

        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)

        self.start_server_button = QPushButton("Start Server")
        self.start_client_button = QPushButton("Start Client")

        # Layout setup
        h_layout = QHBoxLayout()
        h_layout.addWidget(self.ip_label)
        h_layout.addWidget(self.ip_input)
        h_layout.addWidget(self.port_label)
        h_layout.addWidget(self.port_input)

        v_layout = QVBoxLayout()
        v_layout.addLayout(h_layout)
        v_layout.addWidget(self.log)
        v_layout.addWidget(self.msg_input)
        v_layout.addWidget(self.send_button)
        v_layout.addWidget(self.start_server_button)
        v_layout.addWidget(self.start_client_button)

        self.setLayout(v_layout)

        # Signals
        self.start_server_button.clicked.connect(self.start_server)
        self.start_client_button.clicked.connect(self.start_client)
        self.send_button.clicked.connect(self.send_message)
        self.msg_input.returnPressed.connect(self.send_message)  # Enter key also sends message

        self.client_socket = None
        self.server_socket = None
        self.client_connected = False

    # Aes-GCM encryption helper
    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        encrypted = self.aesgcm.encrypt(nonce, data, None)
        return nonce + encrypted

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    # Server code: handles client connection and communication
    def handle_client(self, client_sock, addr):
        self.log.append(f"[SERVER] Connected by {addr}")
        while True:
            try:
                data = client_sock.recv(4096)
                if not data:
                    break
                decrypted = self.decrypt(data)
                self.log.append(f"[SERVER] Received: {decrypted.decode()}")
                # Echo encrypted response
                response = f"Server Received: {decrypted.decode()}".encode()
                client_sock.send(self.encrypt(response))
            except Exception as e:
                self.log.append(f"[SERVER] Error: {e}")
                break
        client_sock.close()
        self.log.append(f"[SERVER] Connection closed: {addr}")

    def start_server(self):
        host = '0.0.0.0'
        try:
            port = int(self.port_input.text())
        except ValueError:
            self.log.append("[SERVER] Invalid port number")
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.log.append(f"[SERVER] Server listening on {host}:{port}")

        threading.Thread(target=self.accept_client, daemon=True).start()

    def accept_client(self):
        while True:
            client_sock, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()

            # Clients code: connects to server and communicates
    def start_client(self):
        server_ip = self.ip_input.text()
        try:
            port = int(self.port_input.text())
        except ValueError:
            self.log.append("[CLIENT] Invalid port number")
            return

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((server_ip, port))
            self.log.append(f"[CLIENT] Connected to server {server_ip}:{port}")
            self.client_connected = True
            self.msg_input.setEnabled(True)
            self.send_button.setEnabled(True)

            self.msg_input.setFocus(Qt.FocusReason.OtherFocusReason)
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.log.append(f"[CLIENT] Connection failed: {e}")

    def send_message(self):
        if self.client_connected:
            msg = self.msg_input.text()
            if msg.strip() == "":
                return
            try:
                encrypted_msg = self.encrypt(msg.encode())
                self.client_socket.send(encrypted_msg)
                self.log.append(f"[CLIENT] Sent: {msg}")
                self.msg_input.clear()
            except Exception as e:
                self.log.append(f"[CLIENT] Send error: {e}")

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.log.append("[CLIENT] Server disconnected.")
                    self.client_connected = False
                    self.msg_input.setEnabled(False)
                    self.send_button.setEnabled(False)
                    break
                decrypted = self.decrypt(data)
                self.log.append(f"[CLIENT] Server says: {decrypted.decode()}")
            except Exception as e:
                    self.log.append(f"[CLIENT] Received error: {e}")
                    break

def main():
    app = QApplication(sys.argv)
    vpn_gui = VPNGui()
    vpn_gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()