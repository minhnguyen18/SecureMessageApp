#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int socket;
    struct sockaddr_in address;
    socklen_t addr_len;
} Client;

Client clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to broadcast an encrypted message to all clients except the sender
void broadcast_message(int sender_socket, char *message, size_t len) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && clients[i].socket != sender_socket) {
            send(clients[i].socket, message, len, 0);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to handle client communication
void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);
    char buffer[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (bytes_received <= 0) {
            // Handle client disconnect
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == client_socket) {
                    clients[i].socket = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            close(client_socket);
            break;
        }

        // Log that the server received the message (for debugging purposes)
        printf("Encrypted message received from client (len=%ld): ", bytes_received);
        for (ssize_t i = 0; i < bytes_received; i++) {
            printf("%02x", (unsigned char)buffer[i]);
        }
        printf("\n");

        // Send an acknowledgment back to the sender
        char ack_message[] = "Server: Message received";
        send(client_socket, ack_message, strlen(ack_message), 0);

        // Relay the encrypted message to other clients
        broadcast_message(client_socket, buffer, bytes_received);
    }

    return NULL;
}

int main() {
    int server_socket;
    struct sockaddr_in server_address;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0) {
        perror("Socket failed");
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
        int client_socket;
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket == 0) {
                clients[i].socket = client_socket;
                clients[i].address = client_address;
                clients[i].addr_len = client_len;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        int *new_sock = malloc(1);
        *new_sock = client_socket;
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, (void *)new_sock);
        pthread_detach(thread);
    }

    close(server_socket);
    return 0;
}


