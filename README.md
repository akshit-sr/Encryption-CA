Abstract: Secure Messaging System using Tkinter and RSA Encryption

This project implements a secure messaging system using Python's Tkinter for the graphical user interface (GUI) and RSA encryption for secure message transmission. The system allows users to register, log in, send, and receive encrypted messages while ensuring data security and confidentiality.

Key Features:
1. User Authentication:
Users can register with a username and password.
Passwords are securely stored using SHA-256 hashing.

2. RSA Encryption:
Each user is assigned an RSA key pair (public & private keys) at registration.
Messages are encrypted using the recipient's public key and can only be decrypted using their private key.

3. Messaging System:
Users can send encrypted messages to other registered users.
Received messages are decrypted upon retrieval using the user’s private key.

4. Graphical User Interface (GUI):
Built with Tkinter, offering a user-friendly chat interface.
Supports login, registration, message sending, and receiving.

5. File-Based Storage:
User credentials and RSA keys are stored in a JSON-based database.
Encrypted messages are saved as text files for each user.
Working Mechanism:

6. Registration:
Users enter a username and password.
The system generates an RSA key pair and stores it securely.

7. Login:
Users enter their credentials for authentication.

8. Message Transmission:
The sender selects a recipient and types a message.
The message is encrypted using RSA and stored in a file.
The recipient decrypts and reads the message.

9. Applications:
Secure peer-to-peer communication
Confidential messaging for academic or personal use
Basic encryption learning for cybersecurity projects

