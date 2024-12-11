#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h" // Include shared header for server connection and encryption

void login();
void menu();

// Main Function
int main() {
    printf("Secure Messaging Application\n");
    login();
    menu(); // Start the menu
    return 0;
}

// Login Function
void login() {
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];

    printf("Login\n");
    printf("Username: ");
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove newline

    printf("Password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0'; // Remove newline

    // Simple validation for demonstration purposes
    if (strcmp(username, "admin") == 0 && strcmp(password, "password") == 0) {
        printf("Login successful!\n");
    } else {
        printf("Invalid credentials. Exiting.\n");
        exit(1);
    }
}

// Menu Function
void menu() {
    int choice;
    char message[BUFFER_SIZE];

    // Connect to the server when the menu starts
    connect_to_server();

    while (1) {
        printf("\nMenu:\n");
        printf("1. Send a new message\n");
        printf("2. Exit\n");
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Try again.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        getchar(); // Consume newline

        switch (choice) {
            case 1:
                printf("Enter message: ");
                fgets(message, BUFFER_SIZE, stdin);
                message[strcspn(message, "\n")] = '\0'; // Remove newline
                send_message_to_server(message); // Send the message to the server
                break;
            case 2:
                disconnect_from_server(); // Disconnect when exiting
                printf("Goodbye!\n");
                return;
            default:
                printf("Invalid choice. Try again.\n");
        }
    }
}


