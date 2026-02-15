/**
 * aesdsocket.c - AESD Socket Server
 *
 * Behavior:
 *  - Listens on TCP port 9000
 *  - Receives data until '\n' from a client, appends to /var/tmp/aesdsocketdata
 *  - Sends back the entire contents of /var/tmp/aesdsocketdata
 *  - Handles SIGINT/SIGTERM to exit gracefully and remove the data file
 *
 * Notes for Assignment 5 Part 2:
 *  - Uses select() with timeout so shutdown (SIGTERM) doesn't get stuck in accept()
 *  - Handles partial write() / send() and checks realloc()
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define PORT 9000
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define BACKLOG 10
#define BUF_SIZE 1024

static int sockfd = -1;
static volatile sig_atomic_t exit_requested = 0;

static void signal_handler(int signo)
{
    (void)signo;
    exit_requested = 1;
    syslog(LOG_INFO, "Caught signal, exiting");
}

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t total = 0;
    while (total < len)
    {
        ssize_t w = write(fd, p + total, len - total);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            return -1;
        total += (size_t)w;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t total = 0;
    while (total < len)
    {
        ssize_t s = send(fd, p + total, len - total, 0);
        if (s < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (s == 0)
            return -1;
        total += (size_t)s;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        daemon_mode = 1;

    openlog("aesdsocket", 0, LOG_USER);

    // Signals
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    // Do NOT set SA_RESTART so select()/accept() can be interrupted / timed out cleanly
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0)
    {
        syslog(LOG_ERR, "sigaction(SIGINT) failed: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0)
    {
        syslog(LOG_ERR, "sigaction(SIGTERM) failed: %s", strerror(errno));
        return -1;
    }

    // Socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
    {
        syslog(LOG_ERR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // Daemonize after bind (so errors are visible in foreground), before listen/loop.
    if (daemon_mode)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            syslog(LOG_ERR, "fork failed: %s", strerror(errno));
            close(sockfd);
            return -1;
        }
        if (pid > 0)
        {
            // parent exits
            exit(0);
        }

        // child continues
        if (setsid() < 0)
        {
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
            close(sockfd);
            return -1;
        }

        umask(0);

        if (chdir("/") != 0)
        {
            syslog(LOG_ERR, "chdir failed: %s", strerror(errno));
            close(sockfd);
            return -1;
        }

        // Redirect stdio to /dev/null
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0)
        {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2)
                close(devnull);
        }
    }

    if (listen(sockfd, BACKLOG) < 0)
    {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    while (!exit_requested)
    {
        // Use select() so we periodically wake up and check exit_requested.
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int rv = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0)
        {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "select failed: %s", strerror(errno));
            break;
        }
        if (rv == 0)
        {
            // timeout
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &addrlen);
        if (connfd < 0)
        {
            if (errno == EINTR)
                continue;
            if (exit_requested)
                break;
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip)))
            syslog(LOG_INFO, "Accepted connection from %s", client_ip);
        else
            syslog(LOG_INFO, "Accepted connection (inet_ntop failed)");

        char *packet = NULL;
        size_t total_size = 0;
        bool saw_newline = false;
        bool recv_error = false;

        while (!saw_newline)
        {
            char buffer[BUF_SIZE];
            ssize_t bytes = recv(connfd, buffer, sizeof(buffer), 0);
            if (bytes < 0)
            {
                if (errno == EINTR)
                    continue;
                recv_error = true;
                syslog(LOG_ERR, "recv failed: %s", strerror(errno));
                break;
            }
            if (bytes == 0)
            {
                // peer closed
                break;
            }

            char *tmp = realloc(packet, total_size + (size_t)bytes);
            if (!tmp)
            {
                syslog(LOG_ERR, "realloc failed");
                recv_error = true;
                break;
            }
            packet = tmp;

            memcpy(packet + total_size, buffer, (size_t)bytes);
            total_size += (size_t)bytes;

            if (memchr(buffer, '\n', (size_t)bytes))
                saw_newline = true;
        }

        if (!recv_error && packet && total_size > 0)
        {
            int fd = open(FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (fd < 0)
            {
                syslog(LOG_ERR, "open(%s) for append failed: %s", FILE_PATH, strerror(errno));
            }
            else
            {
                if (write_all(fd, packet, total_size) != 0)
                    syslog(LOG_ERR, "write_all failed: %s", strerror(errno));
                close(fd);
            }

            fd = open(FILE_PATH, O_RDONLY);
            if (fd < 0)
            {
                syslog(LOG_ERR, "open(%s) for read failed: %s", FILE_PATH, strerror(errno));
            }
            else
            {
                char sendbuf[BUF_SIZE];
                ssize_t r;
                while ((r = read(fd, sendbuf, sizeof(sendbuf))) > 0)
                {
                    if (send_all(connfd, sendbuf, (size_t)r) != 0)
                    {
                        syslog(LOG_ERR, "send_all failed: %s", strerror(errno));
                        break;
                    }
                }
                if (r < 0)
                    syslog(LOG_ERR, "read failed: %s", strerror(errno));
                close(fd);
            }
        }

        free(packet);

        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip)))
            syslog(LOG_INFO, "Closed connection from %s", client_ip);
        else
            syslog(LOG_INFO, "Closed connection");

        close(connfd);
    }

    if (sockfd >= 0)
        close(sockfd);

    // Required for Part 2 reboot test: ensure no stale file remains after clean shutdown.
    remove(FILE_PATH);

    closelog();
    return 0;
}
