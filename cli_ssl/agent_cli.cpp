#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096
#define MAX_CLIENTS 1024
#define FILE_START_MARKER "file_start:"
#define FILE_END_MARKER "file_end"

typedef struct {
    int fd;
    SSL *ssl;           // 每个客户端的 SSL 对象
    char uid[33];
    int uid_set;
    struct sockaddr_in addr;
} Client;

SSL_CTX *ctx;  // 全局 SSL 上下文

int find_client_by_uid(Client *clients, int client_count, const char *uid) {
    int i;
    for (i = 0; i < client_count; i++) {
        if (clients[i].fd > 0 && clients[i].uid_set && strcmp(clients[i].uid, uid) == 0) {
            return i;
        }
    }
    return -1;
}

int find_client_by_index(Client *clients, int client_count, int index) {
    if (index >= 0 && index < client_count && clients[index].fd > 0) {
        return index;
    }
    return -1;
}

void init_ssl_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());  // 使用旧版兼容方法
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 禁用不安全的 SSLv2 和 SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
}

void print_help() {
    printf("Available built-in commands:\n");
    printf("  set uid <index> <uid>      - Set client UID, e.g., 'set uid 0 client1'\n");
    printf("  select <index|uid>         - Select current client, e.g., 'select 0' or 'select client1'\n");
    printf("  list                       - List all connected clients\n");
    printf("  send_file <src> <dst>      - Send file to client, src is file, dst can be file or directory\n");
    printf("  get_file <src> <dst>       - Get file from client, src is file, dst can be file or directory\n");
    printf("  exit                       - Exit server (requires no client selected)\n");
    printf("  help                       - Show this help message\n");
}

int main(int argc, char *argv[]) {
    int server_fd = -1;
    struct sockaddr_in server_addr;
    Client clients[MAX_CLIENTS];
    int client_count = 0;
    char buffer[BUFFER_SIZE];
    int current_client = -1;
    int port, i;

    memset(clients, 0, sizeof(clients));
    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].ssl = NULL;
    }

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Port must be between 1 and 65535\n");
        return 1;
    }

    init_ssl_context();

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((unsigned short)port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 5) == -1) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Server started, listening on port %d, waiting for clients...\n", port);
    print_help();

    while (1) {
        fd_set readfds;
        int max_fd = server_fd;

        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        for (i = 0; i < client_count; i++) {
            if (clients[i].fd > 0) {
                FD_SET(clients[i].fd, &readfds);
                if (clients[i].fd > max_fd) max_fd = clients[i].fd;
            }
        }
        if (max_fd < STDIN_FILENO) max_fd = STDIN_FILENO;

        struct timeval tv = {5, 0};
        if (select(max_fd + 1, &readfds, NULL, NULL, &tv) < 0) {
            perror("Select failed");
            continue;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
            if (client_fd == -1) {
                perror("Accept failed");
                continue;
            }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(client_fd);
                SSL_free(ssl);
                continue;
            }

            struct timeval client_tv = {5, 0};
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&client_tv, sizeof(client_tv));

            if (client_count < MAX_CLIENTS) {
                clients[client_count].fd = client_fd;
                clients[client_count].ssl = ssl;
                clients[client_count].uid_set = 0;
                clients[client_count].addr = client_addr;
                printf("New client connected: %s:%d (index: %d)\n",
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_count);
                client_count++;
            } else {
                printf("Maximum client limit reached\n");
                SSL_free(ssl);
                close(client_fd);
            }
            printf("> ");
            fflush(stdout);
        }

        for (i = 0; i < client_count; i++) {
            if (clients[i].fd > 0 && FD_ISSET(clients[i].fd, &readfds)) {
                int bytes_received = SSL_read(clients[i].ssl, buffer, BUFFER_SIZE - 1);
                if (bytes_received <= 0) {
                    printf("Client %s:%d (UID: %s) disconnected\n",
                           inet_ntoa(clients[i].addr.sin_addr),
                           ntohs(clients[i].addr.sin_port), clients[i].uid_set ? clients[i].uid : "not set");
                    SSL_free(clients[i].ssl);
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    clients[i].ssl = NULL;
                    if (current_client == i) current_client = -1;
                    continue;
                }
                buffer[bytes_received] = '\0';

                char received_uid[33];
                if (sscanf(buffer, "I am agent client, my uid is %32s", received_uid) == 1) {
                    strncpy(clients[i].uid, received_uid, 32);
                    clients[i].uid[32] = '\0';
                    clients[i].uid_set = 1;
                    printf("Received client UID: %s (index: %d)\n", clients[i].uid, i);

                    char response[BUFFER_SIZE];
                    snprintf(response, sizeof(response), "hello, %s", clients[i].uid);
                    if (SSL_write(clients[i].ssl, response, strlen(response)) <= 0) {
                        ERR_print_errors_fp(stderr);
                        SSL_free(clients[i].ssl);
                        close(clients[i].fd);
                        clients[i].fd = -1;
                        if (current_client == i) current_client = -1;
                    } else {
                        printf("Sent confirmation: %s\n", response);
                    }
                    continue;
                }

                if (strcmp(buffer, "heartbeat") == 0) {
                #if 0
                    printf("Received heartbeat, client %s:%d (UID: %s) is alive\n",
                           inet_ntoa(clients[i].addr.sin_addr),
                           ntohs(clients[i].addr.sin_port), clients[i].uid_set ? clients[i].uid : "not set");
                #endif
                    continue;
                }

                long file_size;
                char file_path[BUFFER_SIZE];
                if (sscanf(buffer, FILE_START_MARKER "%ld:%s", &file_size, file_path) == 2) {
                    struct stat st;
                    char final_path[BUFFER_SIZE];
                    char *basename = strrchr(file_path, '/') ? strrchr(file_path, '/') + 1 : file_path;
                    if (stat(file_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                        snprintf(final_path, sizeof(final_path), "%s/%s", file_path, basename);
                    } else {
                        strncpy(final_path, file_path, sizeof(final_path));
                        final_path[sizeof(final_path) - 1] = '\0';
                    }

                    int fd = open(final_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1) {
                        printf("Cannot create file %s: %s\n", final_path, strerror(errno));
                        continue;
                    }
                    size_t received = 0;
                    while (received < file_size) {
                        size_t remaining = file_size - received;
                        size_t to_receive = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
                        bytes_received = SSL_read(clients[i].ssl, buffer, to_receive);
                        if (bytes_received <= 0) {
                            printf("Failed to receive file data: %s\n", strerror(errno));
                            close(fd);
                            break;
                        }
                        write(fd, buffer, bytes_received);
                        received += bytes_received;
                    }
                    close(fd);
                    if (received == file_size) {
                        printf("Received file %s, size %ld bytes, waiting for file_end\n", final_path, file_size);
                        bytes_received = SSL_read(clients[i].ssl, buffer, strlen(FILE_END_MARKER));
                        if (bytes_received == strlen(FILE_END_MARKER) && strncmp(buffer, FILE_END_MARKER, strlen(FILE_END_MARKER)) == 0) {
                            printf("File transfer completed: %s\n", final_path);
                        } else {
                            printf("Expected " FILE_END_MARKER ", received %d bytes\n", bytes_received);
                        }
                    } else {
                        printf("File %s received incompletely, expected %ld bytes, got %zu bytes\n", final_path, file_size, received);
                    }
                    continue;
                }

                printf("Client %s returned (%d bytes):\n%s\n",
                       clients[i].uid_set ? clients[i].uid : "not set", bytes_received, buffer);
                printf("%s> ", (current_client >= 0 && clients[current_client].uid_set) ? clients[current_client].uid : "");
                fflush(stdout);
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
                perror("Input error");
                continue;
            }

            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) == 0) {
                printf("[DEBUG] Input is empty, skipping send\n");
                continue;
            }

            char command[BUFFER_SIZE];
            strncpy(command, buffer, BUFFER_SIZE - 1);
            command[BUFFER_SIZE - 1] = '\0';

            if (strncmp(command, "set uid ", 8) == 0) {
                int target_index;
                char uid[33];
                if (sscanf(command, "set uid %d %32s", &target_index, uid) != 2) {
                    printf("Format error, use 'set uid <index> <uid>', e.g., 'set uid 0 client1'\n");
                } else {
                    int target_client = find_client_by_index(clients, client_count, target_index);
                    if (target_client == -1) {
                        printf("No client found with index %d\n", target_index);
                    } else {
                        strncpy(clients[target_client].uid, uid, 32);
                        clients[target_client].uid[32] = '\0';
                        clients[target_client].uid_set = 1;
                        if (current_client == -1) current_client = target_client;
                        printf("[DEBUG] Set UID: %s (index: %d)\n", clients[target_client].uid, target_client);
                    }
                }
            } else if (strncmp(command, "select ", 7) == 0) {
                char target[33];
                strncpy(target, command + 7, 32);
                target[32] = '\0';
                int target_client;
                int index;
                if (sscanf(target, "%d", &index) == 1) {
                    target_client = find_client_by_index(clients, client_count, index);
                } else {
                    target_client = find_client_by_uid(clients, client_count, target);
                }
                if (target_client == -1) {
                    printf("No client found with index or UID %s\n", target);
                } else {
                    current_client = target_client;
                    printf("[DEBUG] Switched to client: %s (index: %d)\n", clients[current_client].uid, current_client);
                }
            } else if (strcmp(command, "list") == 0) {
                printf("Currently connected clients:\n");
                for (i = 0; i < client_count; i++) {
                    if (clients[i].fd > 0) {
                        printf("Index: %d, UID: %s, IP: %s:%d\n",
                               i, clients[i].uid_set ? clients[i].uid : "not set",
                               inet_ntoa(clients[i].addr.sin_addr),
                               ntohs(clients[i].addr.sin_port));
                    }
                }
            } else if (strcmp(command, "help") == 0) {
                print_help();
            } else if (strcmp(command, "exit") == 0 && current_client == -1) {
                printf("Exiting server program\n");
                for (i = 0; i < client_count; i++) {
                    if (clients[i].fd > 0) {
                        SSL_free(clients[i].ssl);
                        close(clients[i].fd);
                    }
                }
                close(server_fd);
                SSL_CTX_free(ctx);
                return 0;
            } else if (current_client != -1 && clients[current_client].uid_set) {
                char full_command[BUFFER_SIZE];
                if (strncmp(command, "send_file ", 10) == 0) {
                    char source_path[BUFFER_SIZE];
                    char dest_path[BUFFER_SIZE];
                    if (sscanf(command, "send_file %s %s", source_path, dest_path) != 2) {
                        printf("Format error, use 'send_file <source_path> <dest_path>'\n");
                    } else {
                        struct stat st;
                        if (stat(source_path, &st) == -1 || !S_ISREG(st.st_mode)) {
                            printf("Source path %s must be a file\n", source_path);
                        } else {
                            int fd = open(source_path, O_RDONLY);
                            if (fd == -1) {
                                printf("Cannot open file %s: %s\n", source_path, strerror(errno));
                            } else {
                                off_t file_size = st.st_size;
                                char *basename = strrchr(source_path, '/') ? strrchr(source_path, '/') + 1 : source_path;
                                char final_dest[BUFFER_SIZE];
                                if (stat(dest_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                                    snprintf(final_dest, sizeof(final_dest), "%s/%s", dest_path, basename);
                                } else {
                                    strncpy(final_dest, dest_path, sizeof(final_dest));
                                    final_dest[sizeof(final_dest) - 1] = '\0';
                                }
                                snprintf(full_command, sizeof(full_command), FILE_START_MARKER "%ld:%s", (long)file_size, final_dest);
                                if (SSL_write(clients[current_client].ssl, full_command, strlen(full_command)) <= 0) {
                                    ERR_print_errors_fp(stderr);
                                    SSL_free(clients[current_client].ssl);
                                    close(clients[current_client].fd);
                                    clients[current_client].fd = -1;
                                    current_client = -1;
                                } else {
                                    char file_buffer[BUFFER_SIZE];
                                    ssize_t bytes_read;
                                    size_t total_sent = 0;
                                    while (total_sent < file_size && (bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0) {
                                        if (SSL_write(clients[current_client].ssl, file_buffer, bytes_read) <= 0) {
                                            ERR_print_errors_fp(stderr);
                                            SSL_free(clients[current_client].ssl);
                                            close(clients[current_client].fd);
                                            clients[current_client].fd = -1;
                                            current_client = -1;
                                            break;
                                        }
                                        total_sent += bytes_read;
                                    }
                                    if (total_sent == file_size) {
                                        printf("[DEBUG] Sending " FILE_END_MARKER "\n");
                                        if (SSL_write(clients[current_client].ssl, FILE_END_MARKER, strlen(FILE_END_MARKER)) <= 0) {
                                            ERR_print_errors_fp(stderr);
                                            SSL_free(clients[current_client].ssl);
                                            close(clients[current_client].fd);
                                            clients[current_client].fd = -1;
                                            current_client = -1;
                                        } else {
                                            printf("Sent file %s to client %s at %s, size %ld bytes\n", source_path, clients[current_client].uid, final_dest, file_size);
                                        }
                                    } else {
                                        printf("Failed to send file %s completely, sent %zu of %ld bytes\n", source_path, total_sent, file_size);
                                    }
                                }
                                close(fd);
                            }
                        }
                    }
                } else if (strncmp(command, "get_file ", 9) == 0) {
                    char client_source_path[BUFFER_SIZE];
                    char server_dest_path[BUFFER_SIZE];
                    if (sscanf(command, "get_file %s %s", client_source_path, server_dest_path) != 2) {
                        printf("Format error, use 'get_file <client_source_path> <server_dest_path>'\n");
                    } else {
                        snprintf(full_command, sizeof(full_command), "uid:%s get_file %s %s", clients[current_client].uid, client_source_path, server_dest_path);
                        printf("[DEBUG] Sending command: %s\n", full_command);
                        if (SSL_write(clients[current_client].ssl, full_command, strlen(full_command)) <= 0) {
                            ERR_print_errors_fp(stderr);
                            SSL_free(clients[current_client].ssl);
                            close(clients[current_client].fd);
                            clients[current_client].fd = -1;
                            current_client = -1;
                        }
                    }
                } else {
                    snprintf(full_command, sizeof(full_command), "uid:%s %s", clients[current_client].uid, command);
                    printf("[DEBUG] Sending command: %s\n", full_command);
                    if (SSL_write(clients[current_client].ssl, full_command, strlen(full_command)) <= 0) {
                        ERR_print_errors_fp(stderr);
                        SSL_free(clients[current_client].ssl);
                        close(clients[current_client].fd);
                        clients[current_client].fd = -1;
                        current_client = -1;
                    }
                }
            } else {
                printf("Please use 'set uid <index> <uid>' or 'select <index|uid>' to select a client first\n");
            }
            printf("%s> ", (current_client >= 0 && clients[current_client].uid_set) ? clients[current_client].uid : "");
            fflush(stdout);
        }
    }

    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
