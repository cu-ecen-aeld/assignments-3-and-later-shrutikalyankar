#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/stat.h>

#define PORT 9000
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define BACKLOG 10
#define BUF_SIZE 1024

int sockfd = -1;
volatile sig_atomic_t exit_requested = 0;

void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
        exit_requested = 1;
    }
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        daemon_mode = 1;

    openlog("aesdsocket", 0, LOG_USER);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        return -1;

    if (daemon_mode)
    {
        pid_t pid = fork();
        if (pid < 0) return -1;
        if (pid > 0) exit(0);
        umask(0);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    if (listen(sockfd, BACKLOG) < 0)
        return -1;

    while (!exit_requested)
    {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &addrlen);
        if (connfd < 0)
        {
            if (exit_requested) break;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);

        char *packet = NULL;
        size_t total_size = 0;

        while (1)
        {
            char buffer[BUF_SIZE];
            ssize_t bytes = recv(connfd, buffer, BUF_SIZE, 0);
            if (bytes <= 0) break;

            packet = realloc(packet, total_size + bytes);
            memcpy(packet + total_size, buffer, bytes);
            total_size += bytes;

            if (memchr(buffer, '\n', bytes))
                break;
        }

        if (packet && total_size > 0)
        {
            int fd = open(FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
            write(fd, packet, total_size);
            close(fd);

            fd = open(FILE_PATH, O_RDONLY);
            char sendbuf[BUF_SIZE];
            ssize_t read_bytes;
            while ((read_bytes = read(fd, sendbuf, BUF_SIZE)) > 0)
                send(connfd, sendbuf, read_bytes, 0);
            close(fd);
            free(packet);
        }

        syslog(LOG_INFO, "Closed connection from %s", client_ip);
        close(connfd);
    }

    close(sockfd);
    remove(FILE_PATH);
    closelog();
    return 0;
}
