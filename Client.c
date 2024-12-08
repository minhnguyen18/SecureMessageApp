#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024

const unsigned char encryption_key[] = "0123456789abcdef"; // Shared AES key

void encrypt_message(const unsigned char *message, unsigned char *encrypted, int *encrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    // Initialize encryption context
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, encryption_key, NULL);

    // Encrypt the message
    EVP_EncryptUpdate(ctx, encrypted, &len, message, strlen((const char *)message));
    *encrypted_len = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    *encrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    int client_socket;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];
    char server_reply[BUFFER_SIZE];
    unsigned char encrypted_message[BUFFER_SIZE];
    int encrypted_len;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection to server failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server.\n");

    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';

        // Encrypt the message
        encrypt_message((unsigned char *)buffer, encrypted_message, &encrypted_len);

        // Send the encrypted message
        send(client_socket, encrypted_message, encrypted_len, 0);

        // Wait for acknowledgment from the server
        ssize_t bytes_received = recv(client_socket, server_reply, BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            server_reply[bytes_received] = '\0'; // Null-terminate the message
            printf("Server acknowledgment: %s\n", server_reply);
        }
    }

    close(client_socket);
    return 0;
}
