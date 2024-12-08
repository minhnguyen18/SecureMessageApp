# Secure Messaging Application in C

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Project Requirements](#project-requirements)
  - [Encryption](#encryption)
  - [User Authorization](#user-authorization)
  - [Chat History Storage](#chat-history-storage)
  - [User Interface](#user-interface)
  - [Networking Module](#networking-module)
- [Technologies Used](#technologies-used)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

Since the inception of the internet, securing communications has been a fundamental challenge. Early protocols operated on trust, but with the internet's expansion, this trust became insufficient. The solution lies in encryption, which ensures that intercepted messages are unintelligible to unauthorized parties.

This project aims to develop a **secure messaging application** using the **C programming language**. The application enables users to:
- Send and receive encrypted messages.
- Store encrypted chat history locally.
- Access and decrypt messages only upon successful authentication.

Building this application fosters a deeper understanding of encryption, messaging platforms, and secure software design—critical in a time when global efforts seek to undermine encryption standards.

---

## Features

- **End-to-End Encryption:** All messages are encrypted locally before transmission and decrypted locally upon receipt.
- **User Authentication:** Username and password are required for access.
- **Secure Chat History:** Messages are stored locally in an encrypted format.
- **Custom GUI:** Intuitive chat interface, including login, message input, and a scrollable chat display.
- **Reliable Networking:** TCP socket-based communication ensures secure and real-time message delivery.

---

## Project Requirements

### Encryption
- **Automatic Encryption/Decryption:** Messages encrypt upon sending and decrypt upon receiving.
- **Implementation:** Likely using OpenSSL's AES library. Alternatives include custom XOR-based encryption.
- **Security:** All data remains encrypted in transit and at rest.

### User Authorization
- **Login System:** Users authenticate with a username and password.
- **Verification:** Potential use of authentication APIs or a hashed credentials system.

### Chat History Storage
- **Dynamic Memory:** Messages stored in memory during runtime.
- **Encrypted Files:** Periodic writing to encrypted files for persistence.
- **Resilience:** Files remain encrypted unless the user is authenticated.

### User Interface
- **Login Screen:** Fields for username and password, with error handling.
- **Chat Window:**
  - Text input field.
  - Send a button to initiate encryption and send messages.
  - Scrollable chat area to display decrypted messages.
- **Chat History Viewer:** Option to load and decrypt older messages.

### Networking Module
- **Reliable Delivery:** Use of TCP sockets for message transmission.
- **End-to-End Encryption:** Server relays encrypted messages without decryption.
- **Session Management:** Active connection between client and server for the user session.

## Technology Used
- Programming Language: C
- Encryption Library: OpenSSL (AES encryption)
- Networking: TCP Sockets
- GUI: Custom-built interface using a lightweight library (e.g., GTK or ncurses for CLI-based UI)

## Future Improvements
- User Customization: Allow users to modify the appearance of the chat interface.
- File Attachments: Securely send and receive file attachments.
- Cross-Platform Support: Extend compatibility to multiple operating systems.
- Advanced Encryption: Integration of modern encryption standards like ChaCha20-Poly1305.


