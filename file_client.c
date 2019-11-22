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
#include <sys/stat.h>
#include <fcntl.h>

#define PORT 12345
#define BUF_SIZE 256

int sock;
struct sigaction sa_sigabrt;
char buf[BUF_SIZE] = {};

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

void my_write(int s, void *buf, int size) {
    if (write(s, buf, size) < 1) {
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
	char *end = index(buf, '\x0a');
	*end = '\x00';
}

long long int get_file_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
		perror("fstat");
		exit_routine();
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) {
		perror("assert");
		exit_routine();
    }
    return (long long int) st.st_size;
}

void get_file_name(char *file_name) {
	printf("Please input file path: ");
	fflush(0);
	my_read(0, buf);
	memcpy(file_name, buf, BUF_SIZE);
}

void xxd(char *file_data, int file_size, char *data_hex, int data_hex_size) {
	int i = 0;
	int data_hex_idx = 0;
	for (i = 0; i < file_size; i++) {
		char byte = file_data[i];
		char top = (byte & 0xf0) >> 4;
		char bottom = byte & 0x0f;
		if (0 <= top && top <= 9) {
			top = top | 0x30;
		} else {
			top = top - 0xa + 0x61;
		}
		if (0 <= bottom && bottom <= 9) {
			bottom = bottom | 0x30;
		} else {
			bottom = bottom - 0xa + 0x61;
		}
		data_hex[data_hex_idx] = top;
		data_hex_idx++;
		data_hex[data_hex_idx] = bottom;
		data_hex_idx++;
	}
	printf("data_hex: %s\n", data_hex);
}

void usage() {
	printf("Usage: file_client <IP_ADDR>");
	exit(1);
}

int main(int argc, char *argv[]) {
    register_sigaction();
    struct sockaddr_in addr;
	sock = create_sock();
	if (argc < 2) {
		usage();
	}
	if (strncmp(argv[1], "-h", 2) == 0) {
		usage();
	}
	char *ip_addr = argv[1];
    create_addr(&addr, ip_addr);
    socklen_t addr_len = sizeof(addr);
	my_connect(&addr, addr_len);

	char file_name[BUF_SIZE];
	printf("Please input file path: ");
	fflush(0);
	my_read(0, file_name);
	printf("got file_name: %s\n", file_name);
	my_write(sock, file_name, BUF_SIZE);

	char new_file_name[BUF_SIZE];
	printf("Please input new file path: ");
	fflush(0);
	my_read(0, new_file_name);
	printf("got new_file_name: %s\n", new_file_name);
	my_write(sock, new_file_name, BUF_SIZE);

	int f = open(file_name, O_RDONLY);
	if (f < 0) {
		perror("open");
		exit_routine();
	}

	int file_size = get_file_size(f);
	printf("file_size: %d\n", file_size);

	int data_hex_size = file_size * 2;
	printf("data_hex_size: %d\n", data_hex_size);
	my_write(sock, (void *) &data_hex_size, sizeof(int));

	char file_data[file_size];
	memset(file_data, 0, file_size);
	int res = 0;
	while (res < file_size) {
		res += read(f, file_data, file_size);
	}
	close(f);
	printf("file_data: %s\n", file_data);

	char data_hex[data_hex_size];
	memset(data_hex, 0, data_hex_size);
    xxd(file_data, file_size, data_hex, data_hex_size);

	my_write(sock, data_hex, data_hex_size);
	close(sock);
    return 0;
}
