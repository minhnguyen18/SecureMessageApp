#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Function prototypes for encryption and networking
void encrypt_message(const unsigned char *message, unsigned char *encrypted, int *encrypted_len);
void decrypt_message(const unsigned char *encrypted, int encrypted_len, unsigned char *decrypted, int *decrypted_len); // Add this line
void connect_to_server();
void send_message_to_server(const char *message);
void disconnect_from_server();

#endif // COMMON_H

