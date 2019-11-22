#include <stdio.h>
#include <sys/types.h>  
#include <sys/stat.h>
#include <fcntl.h>
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
char buf[BUF_SIZE] = {};

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

void my_write(int s, char *buf, int size) {
    if (write(s, buf, size) < 1) {
        perror("write");
        exit_routine();
    }
}

void my_read(int s, char *buf, int size) {
	memset(buf, 0, size);
	if (read(s, buf, size) < 0) {
	    perror("read");
	    exit_routine();
	}
}

void revert_xxd(char *data, char *data_hex, int data_hex_size) {
	int i = 0;
	int data_idx = 0;
	for (i = 0; i < data_hex_size; i = i + 2) {
		char top = data_hex[i];
		char bottom = data_hex[i+1];
		if (0x30 <= top && top <= 0x39) {
			top = top - 0x30;
		} else {
			top = top - 0x61 + 0xa;
		}
		top = top << 4;
		if (0x30 <= bottom && bottom <= 0x39) {
			bottom = bottom - 0x30;
		} else {
			bottom = bottom - 0x61 + 0xa;
		}
		int top_bottom = top + bottom;
		data[data_idx] = top_bottom;
		data_idx++;
	}
	printf("data: %s\n", data);
}

void main_routine(struct sockaddr_in *addr, socklen_t addr_len) {
    printf("start!\n");

    client = dequeue_one_request(addr, addr_len);
    printf("dequeued!\n");

	char file_name[BUF_SIZE] = {};
    my_read(client, file_name, BUF_SIZE);
    printf("got file_name: %s\n", file_name);

	char new_file_name[BUF_SIZE] = {};
	my_read(client, new_file_name, BUF_SIZE);
	printf("new_file_name: %s\n", new_file_name);

	my_read(client, buf, sizeof(int));
	int data_hex_size = *buf;
	int file_size = data_hex_size / 2;
	printf("data_hex_size: %d\n", data_hex_size);
	printf("file_size: %d\n", file_size);

	char data_hex[data_hex_size];
	memset(data_hex, 0, data_hex_size);
    my_read(client, data_hex, data_hex_size);
    printf("got data_hex: %s\n", data_hex);

	char data[file_size];
	memset(data, 0, file_size);
	revert_xxd(data, data_hex, data_hex_size);

	remove(new_file_name);
    int f = open(new_file_name, O_RDWR|O_CREAT);
	if (f < 0) {
		perror("open");
		exit_routine();
	}
    my_write(f, data, file_size);

	close(f);
    printf("wrote: %s\n", data_hex);
    exit_routine();
}

int main(void) {
    register_sigaction();
    struct sockaddr_in addr;
    sock = create_sock();
    create_addr(&addr);
    socklen_t addr_len = sizeof(addr);
    my_bind(addr, addr_len);
    my_listen();
    main_routine(&addr, addr_len);
    return 0;
}
