#include <stdio.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#define PORT 12345
#define BUF_SIZE 256

int sock;
struct sigaction sa_sigabrt;

void exit_routine(void) {
    close(sock);
    exit(0);
}

void handler(int sig, sigset_t *info, void *ctx) {
    printf("aborted!\n");
    exit_routine();
}

void register_sigaction() {
    memset(&sa_sigabrt, 0, sizeof(sa_sigabrt));
    sa_sigabrt.sa_sigaction = (void *) handler;
    sa_sigabrt.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa_sigabrt, NULL) < 0) {
        perror("sigaction");
        exit_routine();
    }
}

int create_sock() {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    return sock;
}

void create_addr(struct sockaddr_in *addr, char *addr_str) {
    memset(addr, 0, sizeof(addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(addr_str);
    addr->sin_port = htons(PORT);
}

void my_write(int s, char *buf) {
    if (write(s, buf, strlen(buf)) < 1) {
        perror("write");
        exit_routine();
    }
}

void my_connect(struct sockaddr_in *addr, socklen_t addr_len) {
    if (connect(sock, (struct sockaddr *) addr, addr_len) < 0) {
        perror("connect");
        exit_routine();
    }
}

void my_read(int s, char *buf) {
    memset(buf, 0, BUF_SIZE);
    if (read(s, buf, BUF_SIZE) < 0) {
        perror("read");
        exit_routine();
    }
}

int main(void) {
    register_sigaction();
    struct sockaddr_in addr;
    int n;
    sock = create_sock();
    create_addr(&addr, "127.0.0.1");
    socklen_t addr_len = sizeof(addr);
    my_connect(&addr, addr_len);
    char buf[BUF_SIZE] = {};
    my_read(sock, buf);
    printf("%s", buf);
    fflush(0);
    my_read(0, buf);
    my_write(sock, buf);
    close(sock);
    return 0;
}
