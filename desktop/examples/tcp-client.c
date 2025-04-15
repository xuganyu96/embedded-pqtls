/**
 * A TLS 1.3 client combined with a WolfSSL sniffer to capture and analyze the
 * messages
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HTTPS_PORT 443
#define DEFAULT_HOSTNAME "www.raspberrypi.com"

void inspect_hostname(const char *name) {
  // TODO: gethostbyname is obsolete? use getaddrinto and getnameinfo instead
  struct hostent *server = gethostbyname(name);
  printf("%s\n", server->h_name);
  int i = 0;
  while (1) {
    if (!server->h_aliases[i]) {
      break;
    }
    printf("alias %d: %s\n", i, server->h_aliases[i]);
    i++;
  }
}

int main(int argc, char **argv) {
  char *hostname = (argc < 2) ? DEFAULT_HOSTNAME : argv[1];
  // inspect_hostname(hostname);
  struct hostent *server = gethostbyname(hostname);
  if (!server) {
    fprintf(stderr, "Failed to resolve hostname %s\n", hostname);
  }

  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    fprintf(stderr, "Failed to open socket\n");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(HTTPS_PORT);
  memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

  fprintf(stderr, "Connecting to %s:%d\n", hostname, HTTPS_PORT);
  int fail =
      connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (fail < 0) {
    fprintf(stderr, "Failed to connect to %s:%d\n", hostname, HTTPS_PORT);
    exit(EXIT_FAILURE);
  } else {
    printf("Connected to %s:%d\n", hostname, HTTPS_PORT);
  }

  close(sock_fd);
  return 0;
}
