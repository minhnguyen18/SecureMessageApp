#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define ENCRYPTION_KEY "0123456789abcdef" // 16-byte key for AES-128-ECB

typedef struct {
    int socket;
    char username[50];
} Client;

Client clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Encryption Function
void encrypt_message(const char *message, unsigned char *encrypted, int *encrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)ENCRYPTION_KEY, NULL);
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)message, strlen(message));
    *encrypted_len = len;

    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    *encrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Decryption Function
void decrypt_message(const unsigned char *encrypted, int encrypted_len, char *decrypted, int *decrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)ENCRYPTION_KEY, NULL);
    EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &len, encrypted, encrypted_len);
    *decrypted_len = len;

    EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + len, &len);
    *decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Broadcast a message to all clients except the sender
void broadcast_message(int sender_socket, const char *message, size_t len) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && clients[i].socket != sender_socket) {
            send(clients[i].socket, message, len, 0);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Send a message to a specific client
void send_to_user(const char *recipient, const char *encrypted_message, int message_len, int sender_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && strcmp(clients[i].username, recipient) == 0) {
            send(clients[i].socket, encrypted_message, message_len, 0);
            pthread_mutex_unlock(&clients_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Notify sender if recipient is not found
    send(sender_socket, "Error: User not found.\n", 23, 0);
}

// Handle communication with a specific client
void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);
    unsigned char buffer[BUFFER_SIZE];
    char decrypted[BUFFER_SIZE];
    int decrypted_len;
    char username[50];

    // Receive and register username
    if (recv(client_socket, username, sizeof(username), 0) <= 0) {
        close(client_socket);
        return NULL;
    }
    username[strcspn(username, "\n")] = '\0'; // Remove newline character

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == 0) {
            clients[i].socket = client_socket;
            strncpy(clients[i].username, username, sizeof(clients[i].username) - 1);
            printf("User %s connected.\n", username);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Handle messages from the client
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (bytes_received <= 0) {
            // Handle client disconnect
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == client_socket) {
                    printf("User %s disconnected.\n", clients[i].username);
                    clients[i].socket = 0;
                    memset(clients[i].username, 0, sizeof(clients[i].username));
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            close(client_socket);
            break;
        }
        // Print out the encrypted message
        printf("Encrypted message received: ");
        for (ssize_t i = 0; i < bytes_received; i++) {
            printf("%02x ", buffer[i]);
        }
        printf("\n");
        // Decrypt the received message
        decrypt_message(buffer, bytes_received, decrypted, &decrypted_len);
        decrypted[decrypted_len] = '\0'; // Null-terminate the decrypted string

        // Parse recipient and message
        char *recipient = strtok(decrypted, ":");
        char *message = strtok(NULL, "");

        if (recipient && message) {
            // Re-encrypt the message for the recipient
            unsigned char re_encrypted[BUFFER_SIZE];
            int re_encrypted_len;
            encrypt_message(message, re_encrypted, &re_encrypted_len);

            send_to_user(recipient, (char *)re_encrypted, re_encrypted_len, client_socket);
        } else {
            send(client_socket, "Error: Invalid message format. Use recipient:message\n", 54, 0);
        }
    }

    return NULL;
}

int main() {
    int server_socket;
    struct sockaddr_in server_address;

    // Initialize client slots
    memset(clients, 0, sizeof(clients));

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server started. Waiting for connections...\n");

    while (1) {
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_len);

        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        int *new_sock = malloc(sizeof(int));
        *new_sock = client_socket;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, (void *)new_sock);
        pthread_detach(thread);
    }

    close(server_socket);
    return 0;
}



