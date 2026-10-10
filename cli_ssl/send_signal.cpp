#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <pid> <port>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    int port = atoi(argv[2]);

    union sigval value;
    value.sival_int = port;

    if (sigqueue(pid, SIGUSR1, value) == -1) {
        perror("sigqueue failed");
        return 1;
    }

    printf("Sent SIGUSR1 with port %d to PID %d\n", port, pid);
    return 0;
}
