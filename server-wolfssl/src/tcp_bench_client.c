/**
 * A TCP client that benchmarks the TCP stack
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HOSTNAME_MAX_SIZE 1024
#define BENCH_DURATION 5 // 5 seconds
#define HELP_DOC "Usage: tcp_bench_client <hostname> <port>"

typedef struct cli_args {
  char hostname[HOSTNAME_MAX_SIZE];
  uint16_t port;
} cli_args_t;

void cli_args_init(cli_args_t *args) { memset(args, 0, sizeof(cli_args_t)); }

int cli_args_parse(int argc, char *argv[], cli_args_t *args) {
  if (argc != 3) {
    printf("%s\n", HELP_DOC);
    return 1;
  }
  strncpy(args->hostname, argv[1], HOSTNAME_MAX_SIZE);
  args->port = atoi(argv[2]);
  if (args->port < 1 || args->port > 65535) {
    fprintf(stderr, "Invalid port %d\n", args->port);
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  cli_args_t args;
  cli_args_init(&args);
  if (cli_args_parse(argc, argv, &args) != 0) {
    fprintf(stderr, "Failed to parse CLI args\n");
    exit(EXIT_FAILURE);
  }
  printf("Benchmarking TCP connection to %s:%d\n", args.hostname, args.port);

  struct hostent *peer_dns = gethostbyname(args.hostname);
  if (!peer_dns) {
    fprintf(stderr, "Failed to resolve hostname %s\n", args.hostname);
  }
  struct sockaddr_in peer_addr;
  memset(&peer_addr, 0, sizeof(peer_addr));
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(args.port);
  memcpy(&peer_addr.sin_addr.s_addr, peer_dns->h_addr, peer_dns->h_length);
  printf("Hostname %s resolved to %s\n", args.hostname,
         inet_ntoa(peer_addr.sin_addr));

  time_t start_time = time(0);
  time_t now;
  size_t cnt = 0;
  int sockfd;
  do {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
      fprintf(stderr, "Failed to create socket\n");
      exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
      fprintf(stderr, "Failed to connect to peer\n");
      exit(EXIT_FAILURE);
    }

    close(sockfd);
    cnt++;
    now = time(0);
  } while (now - start_time < BENCH_DURATION);
  printf("Connections established: %zu in %d seconds (%.2f connections/sec)\n",
         cnt, BENCH_DURATION, (float)cnt / BENCH_DURATION);

  return 0;
}
