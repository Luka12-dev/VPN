VPN.exe — Simple Encrypted Chat Application with GUI
Overview
VPN.exe is a standalone Windows application providing encrypted TCP chat functionality. It uses AES-GCM 256-bit encryption to secure all messages exchanged between client and server. The user-friendly GUI enables easy server and client setup, message sending, and logging.

Features
Run as either server or client in one app

AES-GCM encryption ensures message confidentiality

Responsive GUI with PyQt6 design

Multithreaded communication to avoid freezing UI

Single executable file, no installation needed

How to Use
Start Server

Enter the port number you want the server to listen on (default: 9999)

Click Start Server button

The server will begin listening for client connections

Start Client

Enter the IP address of the server to connect to (default: 127.0.0.1)

Enter the server port (default: 9999)

Click Start Client button

Once connected, you can send encrypted messages

Send Messages

Type your message in the input box

Press Enter or click Send to transmit encrypted message

Important Notes
The encryption key is generated fresh each time the app starts. For real-world use, key management or exchange would be required.

Ensure the server is running before starting the client to avoid connection errors.

Windows Firewall or antivirus software may block connections; add an exception if needed.

Troubleshooting
If connection fails with “connection refused,” verify the server is active and listening on the correct IP and port.

Change the port number if it conflicts with other apps.

Run as administrator if networking issues persist.

License
This software is provided as-is for educational and demonstration purposes. Use responsibly.