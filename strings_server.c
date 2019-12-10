#include <stdio.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#define PORT 12345
#define BUF_SIZE 256

int sock;
int client;
struct sigaction sa_sigabrt;

void exit_routine(void) {
    close(client);
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

void create_addr(struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    addr->sin_port = htons(PORT);
}

void my_bind(struct sockaddr_in addr, socklen_t addr_len) {
    if (bind(sock, (struct sockaddr *) &addr, addr_len) < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }
}

void my_listen() {
    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        exit(1);
    }
}

int dequeue_one_request(struct sockaddr_in *addr, socklen_t addr_len) {
    client = accept(sock, (struct sockaddr*) addr, &addr_len);
    if (client < 0) {
        perror("accept");
        exit_routine();
    }
    return client;
}

void my_write(int s, char *buf) {
    if (write(s, buf, strlen(buf)) < 1) {
        perror("write");
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
    char buf[BUF_SIZE] = {};
    struct sockaddr_in addr;
    int n;
    sock = create_sock();
    create_addr(&addr);
    socklen_t addr_len = sizeof(addr);
    my_bind(addr, addr_len);
    my_listen();
    while (1) {
        client = dequeue_one_request(&addr, addr_len);
        char *please_input = "Please input some strings: ";
        my_write(client, please_input);
        my_read(client, buf);
        printf("%s\n", buf);
        close(client);
    }
    return 0;
}
