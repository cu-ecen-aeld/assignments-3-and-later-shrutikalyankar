#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PORT "9000"
#define DATAFILE "/var/tmp/aesdsocketdata"
#define BACKLOG 10

static volatile sig_atomic_t exit_requested = 0;
static int serverfd_global = -1;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================= THREAD STRUCT ================= */
struct thread_node {
    pthread_t thread_id;
    int clientfd;
    bool thread_complete;
    struct thread_node *next;
};

static struct thread_node *thread_list_head = NULL;

/* ================= SIGNAL HANDLER ================= */
static void signal_handler(int signo)
{
    (void)signo;
    exit_requested = 1;

    if (serverfd_global != -1) {
        close(serverfd_global);   // unblock accept
        serverfd_global = -1;
    }
}

/* ================= SOCKET SETUP ================= */
static int create_server_socket(void)
{
    struct addrinfo hints, *res, *p;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, PORT, &hints, &res) != 0)
        return -1;

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == 0)
            break;

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    if (sockfd < 0) return -1;

    if (listen(sockfd, BACKLOG) != 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/* ================= DAEMONIZE ================= */
static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) return -1;

    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);

    if (chdir("/") != 0)
        return -1;

    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) return -1;

    if (dup2(fd, STDIN_FILENO) < 0) return -1;
    if (dup2(fd, STDOUT_FILENO) < 0) return -1;
    if (dup2(fd, STDERR_FILENO) < 0) return -1;

    if (fd > 2)
        close(fd);

    return 0;
}

/* ================= FILE HELPERS ================= */
static int append_to_file(const char *buf, size_t len)
{
    int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;

    size_t written = 0;
    while (written < len) {
        ssize_t rc = write(fd, buf + written, len - written);
        if (rc < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        written += rc;
    }

    close(fd);
    return 0;
}

static int send_full_file(int clientfd)
{
    int fd = open(DATAFILE, O_RDONLY);
    if (fd < 0) return -1;

    char buffer[4096];
    ssize_t r;

    while ((r = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t sent = 0;
        while (sent < r) {
            ssize_t s = send(clientfd, buffer + sent, r - sent, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            sent += s;
        }
    }

    close(fd);
    return 0;
}

/* ================= TIMESTAMP THREAD ================= */
static void *timestamp_thread(void *arg)
{
    (void)arg;

    while (!exit_requested) {
        for (int i = 0; i < 10 && !exit_requested; i++)
            sleep(1);

        if (exit_requested) break;

        time_t now = time(NULL);
        struct tm tm_now;
        localtime_r(&now, &tm_now);

        char timestr[128];
        strftime(timestr, sizeof(timestr),
                 "%a, %d %b %Y %H:%M:%S %z", &tm_now);

        char line[256];
        int len = snprintf(line, sizeof(line),
                           "timestamp:%s\n", timestr);

        pthread_mutex_lock(&file_mutex);
        append_to_file(line, (size_t)len);
        pthread_mutex_unlock(&file_mutex);
    }

    return NULL;
}

/* ================= CLIENT THREAD ================= */
static void *client_thread(void *arg)
{
    struct thread_node *node = (struct thread_node *)arg;
    int clientfd = node->clientfd;

    char *packet = NULL;
    size_t packet_size = 0;

    while (!exit_requested) {
        char buf[1024];
        ssize_t r = recv(clientfd, buf, sizeof(buf), 0);
        if (r <= 0) break;

        char *tmp = realloc(packet, packet_size + r);
        if (!tmp) break;

        packet = tmp;
        memcpy(packet + packet_size, buf, r);
        packet_size += r;

        char *newline;
        while ((newline = memchr(packet, '\n', packet_size)) != NULL) {
            size_t pkt_len = (newline - packet) + 1;

            pthread_mutex_lock(&file_mutex);

            append_to_file(packet, pkt_len);
            send_full_file(clientfd);

            pthread_mutex_unlock(&file_mutex);

            size_t remaining = packet_size - pkt_len;
            memmove(packet, packet + pkt_len, remaining);
            packet_size = remaining;
        }
    }

    free(packet);
    shutdown(clientfd, SHUT_RDWR);
    close(clientfd);

    node->thread_complete = true;
    return NULL;
}

/* ================= MAIN ================= */
int main(int argc, char *argv[])
{
    openlog("aesdsocket", LOG_PID, LOG_USER);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        if (daemonize() != 0) {
            syslog(LOG_ERR, "Daemonize failed");
            return -1;
        }
    }

    int serverfd = create_server_socket();
    if (serverfd < 0) {
        syslog(LOG_ERR, "Socket setup failed");
        return -1;
    }

    serverfd_global = serverfd;

    pthread_t ts_thread;
    pthread_create(&ts_thread, NULL, timestamp_thread, NULL);

    while (!exit_requested) {

        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int clientfd = accept(serverfd,
                              (struct sockaddr *)&client_addr,
                              &addrlen);

        if (clientfd < 0) {
            if (exit_requested) break;
            if (errno == EINTR) continue;
            break;
        }

        struct thread_node *node =
            malloc(sizeof(struct thread_node));
        if (!node) {
            close(clientfd);
            continue;
        }

        node->clientfd = clientfd;
        node->thread_complete = false;
        node->next = thread_list_head;
        thread_list_head = node;

        pthread_create(&node->thread_id,
                       NULL,
                       client_thread,
                       node);

        /* Cleanup completed threads */
        struct thread_node *curr = thread_list_head;
        struct thread_node *prev = NULL;

        while (curr) {
            if (curr->thread_complete) {
                pthread_join(curr->thread_id, NULL);

                if (prev)
                    prev->next = curr->next;
                else
                    thread_list_head = curr->next;

                struct thread_node *tmp = curr;
                curr = curr->next;
                free(tmp);
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
    }

    /* Join remaining threads */
    struct thread_node *curr = thread_list_head;
    while (curr) {
        pthread_join(curr->thread_id, NULL);
        struct thread_node *tmp = curr;
        curr = curr->next;
        free(tmp);
    }

    pthread_join(ts_thread, NULL);

    if (serverfd != -1)
        close(serverfd);

    unlink(DATAFILE);
    pthread_mutex_destroy(&file_mutex);
    closelog();

    return 0;
}
