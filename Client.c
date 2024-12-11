#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "common.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define ENCRYPTION_KEY "0123456789abcdef"
#define HISTORY_FILE "chat_history.enc"

// Global socket
static int client_socket;

// Forward declarations
void send_message_to_user(const char *recipient, const char *message);
void save_message(const unsigned char *message, int message_len);
void load_message_history();
void encrypt_message(const unsigned char *message, unsigned char *encrypted, int *encrypted_len);
void decrypt_message(const unsigned char *encrypted, int encrypted_len, unsigned char *decrypted, int *decrypted_len);

// Function to save a message to an encrypted file
void save_message(const unsigned char *message, int message_len) {
    FILE *file = fopen(HISTORY_FILE, "ab");
    if (!file) {
        perror("Failed to open history file");
        return;
    }
    fwrite(message, 1, message_len, file);
    fclose(file);
}

// Function to load and decrypt message history
void load_message_history() {
    FILE *file = fopen(HISTORY_FILE, "rb");
    if (!file) {
        perror("Failed to open history file");
        return;
    }

    unsigned char encrypted[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    int decrypted_len;
    size_t bytes_read;

    printf("\nChat History:\n");
    while ((bytes_read = fread(encrypted, 1, BUFFER_SIZE, file)) > 0) {
        decrypt_message(encrypted, bytes_read, decrypted, &decrypted_len);
        decrypted[decrypted_len] = '\0'; // Null-terminate string
        printf("%s\n", decrypted);
    }

    fclose(file);
}

// Encrypt a message
void encrypt_message(const unsigned char *message, unsigned char *encrypted, int *encrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)ENCRYPTION_KEY, NULL);
    EVP_EncryptUpdate(ctx, encrypted, &len, message, strlen((const char *)message));
    *encrypted_len = len;

    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    *encrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Decrypt a message
void decrypt_message(const unsigned char *encrypted, int encrypted_len, unsigned char *decrypted, int *decrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)ENCRYPTION_KEY, NULL);
    EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len);
    *decrypted_len = len;

    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    *decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Function to receive messages in a separate thread
void *receive_messages(void *arg) {
    int client_socket = *((int *)arg);
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    int decrypted_len, encrypted_len;

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (bytes_received > 0) {
            decrypt_message(buffer, bytes_received, decrypted, &decrypted_len);
            decrypted[decrypted_len] = '\0'; // Null-terminate the string
            printf("Message received: %s\n", decrypted);

            // Re-encrypt and save the message to the file
            encrypt_message((unsigned char *)decrypted, encrypted, &encrypted_len);
            save_message(encrypted, encrypted_len);
        } else if (bytes_received == 0) {
            printf("Server disconnected.\n");
            break;
        } else {
            perror("Failed to receive message");
            break;
        }
    }

    return NULL;
}

// Connect to the server
void connect_to_server(const char *username) {
    struct sockaddr_in server_address;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection to server failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    send(client_socket, username, strlen(username), 0);
    printf("Connected to server as %s.\n", username);
}

// Send a message to a specific recipient
void send_message_to_user(const char *recipient, const char *message) {
    char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    int encrypted_len;

    snprintf(buffer, sizeof(buffer), "%s:%s", recipient, message);
    encrypt_message((unsigned char *)buffer, encrypted, &encrypted_len);

    if (send(client_socket, encrypted, encrypted_len, 0) == -1) {
        perror("Failed to send message");
    }
}

// Login function
void login(char *username) {
    printf("Login\n");
    printf("Username: ");
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove newline
}

// Menu function
void menu(const char *username) {
    pthread_t receive_thread;
    pthread_create(&receive_thread, NULL, receive_messages, &client_socket);
    pthread_detach(receive_thread);

    int choice;
    char recipient[BUFFER_SIZE];
    char message[BUFFER_SIZE];

    while (1) {
        printf("\nMenu:\n");
        printf("1. Send a message\n");
        printf("2. View chat history\n");
        printf("3. Exit\n");
        printf("Enter your choice:\n");
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Try again.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        getchar(); // Consume newline

        switch (choice) {
            case 1:
                printf("Enter recipient username: ");
                fgets(recipient, BUFFER_SIZE, stdin);
                recipient[strcspn(recipient, "\n")] = '\0';

                printf("Enter message: ");
                fgets(message, BUFFER_SIZE, stdin);
                message[strcspn(message, "\n")] = '\0';

                send_message_to_user(recipient, message);
                break;
            case 2:
                load_message_history();
                break;
            case 3:
                close(client_socket);
                printf("Goodbye!\n");
                return;
            default:
                printf("Invalid choice. Try again.\n");
        }
    }
}

// Main function
int main() {
    char username[BUFFER_SIZE];

    printf("Secure Messaging Application\n");
    login(username);
    connect_to_server(username);
    menu(username);
    return 0;
}

