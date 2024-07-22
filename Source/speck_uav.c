/*
    Developer: Husanboy (후산보이)
    Web: https://husanboy.me
    Email: husanboy.me@gmail.com

    These programs implement secure communication channel between
    Ground Control Station and Unmanned Aerial/Ground Vehicle.
    
    Speck lightweight block cipher for encryption.
    Message Authentication Codes for data integrity.
    TCP protocol for networking.

    Hardware used: Raspberry Pi, Pixhawk, GCS computer.

    Note: These programs are optimized for Linux systems.
    If your system is Windows, please use Windows-Subsystem for Linux
    to run these programs.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define PORT 8080
#define BUFFER_SIZE 256
#define ROUNDS 32
#define WORD_SIZE 32
#define BLOCK_SIZE (WORD_SIZE / 8) * 2 // Block size in bytes for each plaintext block (e.g., 8 bytes for 32-bit words)
#define HMAC_SIZE SHA256_DIGEST_LENGTH

uint32_t key[4];
uint8_t hmac_key[16] = "secret_hmac_key"; // HMAC key (for demonstration purposes, should be kept secret and secure)

void speck_encrypt(uint32_t *x, uint32_t *y, uint32_t *k) {
    uint32_t v = *x, w = *y;
    uint32_t sum = 0, delta = 0x9e3779b9;

    for (int i = 0; i < ROUNDS; i++) {
        v = (v >> 8) | (v << (WORD_SIZE - 8)); // Rotate right 8
        v = (v + w) & 0xFFFFFFFF;              // Add w
        v ^= k[i % 4];                         // XOR with round key
        w = (w << 3) | (w >> (WORD_SIZE - 3)); // Rotate left 3
        w ^= v;                                // XOR with v
    }

    *x = v;
    *y = w;
}

void speck_decrypt(uint32_t *x, uint32_t *y, uint32_t *k) {
    uint32_t v = *x, w = *y;
    uint32_t sum = 0xc6ef3720, delta = 0x9e3779b9;

    for (int i = ROUNDS - 1; i >= 0; i--) {
        w ^= v;                                // XOR with v
        w = (w >> 3) | (w << (WORD_SIZE - 3)); // Rotate right 3
        v ^= k[i % 4];                         // XOR with round key
        v = (v - w) & 0xFFFFFFFF;              // Subtract w
        v = (v << 8) | (v >> (WORD_SIZE - 8)); // Rotate left 8
    }

    *x = v;
    *y = w;
}

void pad_data(uint8_t *data, size_t data_len, size_t block_size, uint8_t **padded_data, size_t *padded_len) {
    size_t padding_len = block_size - (data_len % block_size);
    *padded_len = data_len + padding_len;
    *padded_data = (uint8_t *)malloc(*padded_len);
    memcpy(*padded_data, data, data_len);
    memset(*padded_data + data_len, padding_len, padding_len); // PKCS7 padding
}

void unpad_data(uint8_t *padded_data, size_t padded_len, uint8_t **data, size_t *data_len) {
    size_t padding_len = padded_data[padded_len - 1];
    *data_len = padded_len - padding_len;
    *data = (uint8_t *)malloc(*data_len);
    memcpy(*data, padded_data, *data_len);
}

void print_data(const char *label, uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void get_key() {
    // Get key from user
    printf("Enter key (4 words separated by space): ");
    scanf("%x %x %x %x", &key[0], &key[1], &key[2], &key[3]);
}

void compute_hmac(uint8_t *data, size_t data_len, uint8_t *hmac_output) {
    unsigned int len;
    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key), data, data_len, hmac_output, &len);
}

int verify_hmac(uint8_t *data, size_t data_len, uint8_t *received_hmac) {
    uint8_t computed_hmac[HMAC_SIZE];
    compute_hmac(data, data_len, computed_hmac);
    return memcmp(received_hmac, computed_hmac, HMAC_SIZE) == 0;
}

int main() {
    struct sockaddr_in serv_addr;
    int sock = 0, valread;
    char buffer[BUFFER_SIZE] = {0};

    // Create TCP socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form.
    // Change '127.0.0.1' to your Ground Control Station public IP.
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Get key from user
    get_key();

    // Main loop
    while (1) {
        // Get input from user
        printf("UAV: Enter reply to GCS (max %d characters): ", BUFFER_SIZE);
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

        size_t data_len = strlen(buffer);
        uint8_t *encrypted_data;
        size_t encrypted_len;

        pad_data((uint8_t *)buffer, data_len, BLOCK_SIZE, &encrypted_data, &encrypted_len);

        // Encrypt data block by block
        for (size_t i = 0; i < encrypted_len; i += BLOCK_SIZE) {
            speck_encrypt((uint32_t *)&encrypted_data[i], (uint32_t *)&encrypted_data[i + WORD_SIZE / 8], key);
        }

        uint8_t hmac_output[HMAC_SIZE];
        compute_hmac(encrypted_data, encrypted_len, hmac_output);

        uint8_t *send_data = (uint8_t *)malloc(encrypted_len + HMAC_SIZE);
        memcpy(send_data, encrypted_data, encrypted_len);
        memcpy(send_data + encrypted_len, hmac_output, HMAC_SIZE);

        // Send encrypted data with HMAC to server
        send(sock, send_data, encrypted_len + HMAC_SIZE, 0);
        printf("Reply Sent.\n");

        // Receive reply from server
        valread = read(sock, buffer, BUFFER_SIZE);
        if (valread <= HMAC_SIZE) {
            printf("Received data is too small to contain valid HMAC\n");
            free(send_data);
            continue;
        }

        printf("Received Cipher Message from GCS: ");
        print_data("", (uint8_t *)buffer, valread);

        uint8_t *received_data = (uint8_t *)buffer;
        size_t received_data_len = valread - HMAC_SIZE;
        uint8_t *received_hmac = (uint8_t *)buffer + received_data_len;

        if (!verify_hmac(received_data, received_data_len, received_hmac)) {
            printf("HMAC verification failed!\n");
            free(send_data);
            continue;
        }

        // Decrypt received data
        uint8_t *decrypted_data;
        size_t decrypted_len;
        uint8_t *padded_data = (uint8_t *)buffer;
        size_t padded_len = received_data_len;

        // Decrypt data block by block
        for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
            speck_decrypt((uint32_t *)&padded_data[i], (uint32_t *)&padded_data[i + WORD_SIZE / 8], key);
        }

        unpad_data(padded_data, padded_len, &decrypted_data, &decrypted_len);

        printf("Decrypted Plain Text: %s\n", decrypted_data);

        free(encrypted_data);
        free(decrypted_data);
        free(send_data);
    }

    close(sock);
    return 0;
}
