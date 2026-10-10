// agent_cli_client.cpp
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <ctype.h>

#define BUFFER_SIZE 4096
#define CONNECT_RETRY_INTERVAL 5
#define FILE_START_MARKER "file_start:"
#define FILE_END_MARKER "file_end"
#define PID_FILE "/tmp/.osec_cli.pid"
#define INI_FILE "/opt/osec/net_info.ini"

//#define LOG_INFO(...) printf("[INFO] " __VA_ARGS__)
//#define LOG_ERROR(...) fprintf(stderr, "[ERROR] " __VA_ARGS__)
#define LOG_INFO(...) 
#define LOG_ERROR(...) 

SSL_CTX *ctx = NULL;
static int sock = -1;
static SSL *ssl = NULL;
static volatile int running = 0;
static pthread_t client_thread;
static char server_ip[32] = ""; // Initialize empty, populated from INI
static int port = 0;
static char dev_uid[64] = "";
static pid_t child_pid = 0;

// Function to trim whitespace from strings and check if empty
bool trim_and_check_non_empty(char *str, char **trimmed_out) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) {
        *trimmed_out = str;
        return false; // Empty after trimming
    }
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
    *trimmed_out = str;
    return true; // Non-empty after trimming
}

// Function to parse SERVER_IP (remove https:// prefix)
bool parse_server_ip(const char *server_ip_input, char *ip_output, size_t ip_output_size) {
    char *trimmed_input;
    if (!trim_and_check_non_empty((char *)server_ip_input, &trimmed_input)) {
        LOG_ERROR("SERVER_IP is empty\n");
        return false;
    }

    const char *prefix = "https://";
    const size_t prefix_len = strlen(prefix);
    
    if (strncmp(trimmed_input, prefix, prefix_len) == 0) {
        strncpy(ip_output, trimmed_input + prefix_len, ip_output_size - 1);
        ip_output[ip_output_size - 1] = '\0';
    } else {
        strncpy(ip_output, trimmed_input, ip_output_size - 1);
        ip_output[ip_output_size - 1] = '\0';
    }

    // Validate IP address format
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip_output, &(sa.sin_addr)) <= 0) {
        LOG_ERROR("Invalid IP address format: %s\n", ip_output);
        return false;
    }
    return true;
}

// Function to parse INI file
bool parse_ini_file(const char *filename, int *cli_port, char *dev_uid_out, char *server_ip_out) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_ERROR("Failed to open INI file %s: %s\n", filename, strerror(errno));
        return false;
    }

    char line[256];
    bool in_clientinfo = false, in_serverinfo = false;
    *cli_port = -1; // Default to invalid port
    dev_uid_out[0] = '\0';
    server_ip_out[0] = '\0';
    bool has_dev_uid = false, has_server_ip = false;

    while (fgets(line, sizeof(line), file)) {
        char *trimmed_line;
        if (!trim_and_check_non_empty(line, &trimmed_line)) continue;

        if (strcmp(trimmed_line, "[CLIENTINFO]") == 0) {
            in_clientinfo = true;
            in_serverinfo = false;
            continue;
        } else if (strcmp(trimmed_line, "[SERVERINFO]") == 0) {
            in_clientinfo = false;
            in_serverinfo = true;
            continue;
        }

        char key[64], value[128];
        if (sscanf(trimmed_line, "%63[^=]=%127[^\n]", key, value) == 2) {
            char *trimmed_key, *trimmed_value;
            if (!trim_and_check_non_empty(key, &trimmed_key) || !trim_and_check_non_empty(value, &trimmed_value)) {
                continue;
            }
            if (in_serverinfo && strcmp(trimmed_key, "CLI_SERVER_PORT") == 0) {
                *cli_port = atoi(trimmed_value);
            } else if (in_serverinfo && strcmp(trimmed_key, "DEV_UID") == 0) {
                strncpy(dev_uid_out, trimmed_value, 63);
                dev_uid_out[63] = '\0';
                has_dev_uid = true;
            } else if (in_serverinfo && strcmp(trimmed_key, "SERVER_IP") == 0) {
                if (!parse_server_ip(trimmed_value, server_ip_out, 32)) {
                    LOG_ERROR("Failed to parse SERVER_IP: %s\n", trimmed_value);
                    fclose(file);
                    return false;
                }
                has_server_ip = true;
            }
        }
    }

    fclose(file);
    if (*cli_port == -1) {
        LOG_ERROR("Missing or invalid CLI_SERVER_PORT in %s\n", filename);
        return false;
    }
    if (!has_dev_uid) {
        LOG_ERROR("DEV_UID is empty or missing in %s\n", filename);
        return false;
    }
    if (!has_server_ip) {
        LOG_ERROR("SERVER_IP is empty or missing in %s\n", filename);
        return false;
    }
    return true;
}

// Check if another instance is running
bool check_single_instance() {
    int pid_fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
    if (pid_fd < 0) {
        LOG_ERROR("Failed to open PID file %s: %s\n", PID_FILE, strerror(errno));
        return false;
    }

    if (flock(pid_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            LOG_ERROR("Another instance is already running (PID file locked)\n");
            close(pid_fd);
            return false;
        }
        LOG_ERROR("Failed to lock PID file: %s\n", strerror(errno));
        close(pid_fd);
        return false;
    }

    char pid_str[16];
    ssize_t bytes_read = read(pid_fd, pid_str, sizeof(pid_str) - 1);
    if (bytes_read > 0) {
        pid_str[bytes_read] = '\0';
        pid_t existing_pid = atoi(pid_str);
        if (existing_pid > 0 && kill(existing_pid, 0) == 0) {
            LOG_ERROR("Another instance is running with PID %d\n", existing_pid);
            flock(pid_fd, LOCK_UN);
            close(pid_fd);
            return false;
        }
    }

    ftruncate(pid_fd, 0);
    lseek(pid_fd, 0, SEEK_SET);
    snprintf(pid_str, sizeof(pid_str), "%d", getpid());
    if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
        LOG_ERROR("Failed to write PID to file: %s\n", strerror(errno));
        flock(pid_fd, LOCK_UN);
        close(pid_fd);
        return false;
    }

    return true;
}

void signal_handler(int sig) {
    if (sig == SIGTERM) {
        LOG_INFO("Received SIGTERM, cleaning up resources\n");
        running = 0;
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;
            LOG_INFO("SSL connection freed\n");
        }
        if (sock >= 0) {
            close(sock);
            sock = -1;
            LOG_INFO("Socket closed\n");
        }
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = NULL;
            LOG_INFO("SSL context freed\n");
        }
        unlink(PID_FILE);
        if (child_pid > 0) {
            kill(child_pid, SIGTERM);
            ::waitpid(child_pid, NULL, 0);
        }
        exit(0);
    }
}

void init_ssl_context() {
    if (ctx) return;
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

void cleanup_resources() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
        LOG_INFO("SSL connection freed\n");
    }
    if (sock >= 0) {
        close(sock);
        sock = -1;
        LOG_INFO("Socket closed\n");
    }
}

void run_client() {
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    while (running) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            LOG_ERROR("Socket creation failed: %s\n", strerror(errno));
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Socket created successfully\n");

        struct timeval tv = {10, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        LOG_INFO("Socket timeout set to 10 seconds\n");

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((unsigned short)port);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            LOG_ERROR("Invalid server IP address: %s\n", server_ip);
            close(sock);
            sock = -1;
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Server address set to %s:%d\n", server_ip, port);

        LOG_INFO("Trying to connect to server %s:%d (PID: %d)...\n", server_ip, port, getpid());
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
            LOG_ERROR("Connect failed: %s\n", strerror(errno));
            close(sock);
            sock = -1;
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("TCP connection established\n");

        ssl = SSL_new(ctx);
        if (!ssl) {
            LOG_ERROR("SSL_new failed\n");
            ERR_print_errors_fp(stderr);
            close(sock);
            sock = -1;
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        SSL_set_fd(ssl, sock);
        int ssl_ret = SSL_connect(ssl);
        if (ssl_ret <= 0) {
            LOG_ERROR("SSL_connect failed, error: %d\n", SSL_get_error(ssl, ssl_ret));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            ssl = NULL;
            close(sock);
            sock = -1;
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
            ssl = NULL;
            close(sock);
            sock = -1;
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Sent UID: %s (%d bytes)\n", uid_msg, write_ret);

        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            LOG_ERROR("SSL_read failed for server response, error: %d\n", SSL_get_error(ssl, bytes_received));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            ssl = NULL;
            close(sock);
            sock = -1;
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
            ssl = NULL;
            close(sock);
            sock = -1;
            sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }
        LOG_INFO("Authentication successful, received: %s\n", expected_response);

        while (running) {
            fd_set readfds;
            struct timeval tv = {5, 0};
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);

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
                continue;
            }

            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received <= 0) {
                LOG_ERROR("SSL_read failed, error: %d\n", SSL_get_error(ssl, bytes_received));
                ERR_print_errors_fp(stderr);
                break;
            }
            buffer[bytes_received] = '\0';

            char result[BUFFER_SIZE] = {0};
            int offset = 0;
            char received_uid[33];
            char command[BUFFER_SIZE];
            long file_size;
            char file_path[BUFFER_SIZE];

            if (sscanf(buffer, "uid:%32s %[^\n]", received_uid, command) == 2) {
                if (strcmp(received_uid, dev_uid) == 0) {
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
                                off_t total_sent = 0;
                                while (total_sent < file_size && (bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0) {
                                    write_ret = SSL_write(ssl, file_buffer, bytes_read);
                                    if (write_ret <= 0) {
                                        LOG_ERROR("SSL_write failed for file_data, error: %d\n", SSL_get_error(ssl, write_ret));
                                        ERR_print_errors_fp(stderr);
                                        close(fd);
                                        break;
                                    }
                                    total_sent += bytes_read;
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
                        FILE *fp = popen(command, "r");
                        if (fp == NULL) {
                            offset += snprintf(result + offset, sizeof(result) - offset,
                                               "Command '%s' execution failed: %s\n", command, strerror(errno));
                            LOG_ERROR("popen failed: %s\n", strerror(errno));
                        } else {
                            size_t total_len = fread(result, 1, BUFFER_SIZE - 1, fp);
                            if (ferror(fp)) {
                                LOG_ERROR("fread error occurred\n");
                                offset += snprintf(result + offset, sizeof(result) - offset,
                                                   "fread error occurred\n");
                            } else {
                                result[total_len] = '\0';
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
                    off_t received = 0;
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

            write_ret = SSL_write(ssl, result, strlen(result));
            if (write_ret <= 0) {
                LOG_ERROR("SSL_write failed for result, error: %d\n", SSL_get_error(ssl, write_ret));
                ERR_print_errors_fp(stderr);
                break;
            }
        }

        cleanup_resources();
        sleep(CONNECT_RETRY_INTERVAL);
    }
}

void *client_thread_func(void *arg) {
    run_client();
    return NULL;
}

int main(int argc, char *argv[]) {
    if (!check_single_instance()) {
        LOG_ERROR("Exiting due to another instance running\n");
        exit(1);
    }

    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        LOG_ERROR("Failed to set SIGTERM handler: %s\n", strerror(errno));
        unlink(PID_FILE);
        exit(1);
    }

    init_ssl_context();

    int last_port = -1;
    char last_dev_uid[64] = "";
    char last_server_ip[32] = "";

    while (1) {
        int cli_port;
        char new_dev_uid[64];
        char new_server_ip[32];
        if (!parse_ini_file(INI_FILE, &cli_port, new_dev_uid, new_server_ip)) {
            if (running) {
                LOG_INFO("Invalid configuration, stopping client\n");
                running = 0;
                cleanup_resources();
                if (pthread_cancel(client_thread) != 0) {
                    LOG_ERROR("Failed to cancel client thread: %s\n", strerror(errno));
                }
                if (pthread_join(client_thread, NULL) != 0) {
                    LOG_ERROR("Failed to join client thread: %s\n", strerror(errno));
                }
            }
            LOG_ERROR("Retrying INI file parse in 5 seconds\n");
            sleep(5);
            continue;
        }

        if (cli_port == 0) {
            if (running) {
                LOG_INFO("CLI_SERVER_PORT is 0, stopping client\n");
                running = 0;
                cleanup_resources();
                if (pthread_cancel(client_thread) != 0) {
                    LOG_ERROR("Failed to cancel client thread: %s\n", strerror(errno));
                }
                if (pthread_join(client_thread, NULL) != 0) {
                    LOG_ERROR("Failed to join client thread: %s\n", strerror(errno));
                }
            }
        } else if (cli_port != last_port || strcmp(new_dev_uid, last_dev_uid) != 0 || strcmp(new_server_ip, last_server_ip) != 0) {
            if (running) {
                LOG_INFO("Configuration changed, restarting client\n");
                running = 0;
                cleanup_resources();
                if (pthread_cancel(client_thread) != 0) {
                    LOG_ERROR("Failed to cancel client thread: %s\n", strerror(errno));
                }
                if (pthread_join(client_thread, NULL) != 0) {
                    LOG_ERROR("Failed to join client thread: %s\n", strerror(errno));
                }
            }

            if (cli_port > 0 && cli_port <= 65535) {
                port = cli_port;
                strncpy(dev_uid, new_dev_uid, sizeof(dev_uid) - 1);
                dev_uid[sizeof(dev_uid) - 1] = '\0';
                strncpy(server_ip, new_server_ip, sizeof(server_ip) - 1);
                server_ip[sizeof(server_ip) - 1] = '\0';
                running = 1;
                LOG_INFO("Starting client with server_ip=%s, port=%d, dev_uid=%s\n",
                         server_ip, port, dev_uid);
                if (pthread_create(&client_thread, NULL, client_thread_func, NULL) != 0) {
                    LOG_ERROR("Failed to create client thread: %s\n", strerror(errno));
                    running = 0;
                }
            } else {
                LOG_ERROR("Invalid port number: %d\n", cli_port);
                if (running) {
                    LOG_INFO("Stopping client due to invalid port\n");
                    running = 0;
                    cleanup_resources();
                    if (pthread_cancel(client_thread) != 0) {
                        LOG_ERROR("Failed to cancel client thread: %s\n", strerror(errno));
                    }
                    if (pthread_join(client_thread, NULL) != 0) {
                        LOG_ERROR("Failed to join client thread: %s\n", strerror(errno));
                    }
                }
            }
        }

        last_port = cli_port;
        strncpy(last_dev_uid, new_dev_uid, sizeof(last_dev_uid) - 1);
        last_dev_uid[sizeof(last_dev_uid) - 1] = '\0';
        strncpy(last_server_ip, new_server_ip, sizeof(last_server_ip) - 1);
        last_server_ip[sizeof(last_server_ip) - 1] = '\0';
        sleep(5); // Check for config changes every 5 seconds
    }

    unlink(PID_FILE);
    if (ctx) {
        SSL_CTX_free(ctx);
        LOG_INFO("SSL context freed\n");
    }
    return 0;
}
