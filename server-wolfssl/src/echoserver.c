/**
 * Simple TCP echo server: after receiving a connection it will send back all
 * bytes it receives
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define HELP_DOC "Usage: echoserver <--port p>"

typedef struct cli_args {
  // required
  uint16_t port;
} cli_args_t;

void cli_args_init(cli_args_t *args) { args->port = 0; }

/**
 * Return 0 on success
 */
int cli_args_parse(int argc, char *argv[], cli_args_t *args) {
  if (argc != 2) {
    printf("%s\n", HELP_DOC);
    return -1;
  }
  args->port = atoi(argv[1]);
  if (args->port < 1 || args->port > 65535) {
    printf("Invalid port number");
  }
  return 0;
}

/**
 * Read from the socket and send back everything it reads
 */
static int stream_handler(int stream) {
  int recv_size, send_size;
  uint8_t buf[4096];

  while (1) {
    recv_size = recv(stream, buf, sizeof(buf), 0);
    if (recv_size == 0) {
      return 0;
    } else if (recv_size < 0) {
      return recv_size;
    }
    send_size = send(stream, buf, recv_size, 0);
    if (send_size < 0) {
      return send_size;
    }
  }
}

int main(int argc, char *argv[]) {
  cli_args_t args;
  cli_args_init(&args);
  if (cli_args_parse(argc, argv, &args) != 0) {
    exit(EXIT_FAILURE);
  }

  int listener, stream, err;
  struct sockaddr_in addr;
  size_t addr_size = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(args.port);
  if (!(listener = socket(AF_INET, SOCK_STREAM, 0))) {
    fprintf(stderr, "Failed to create listener\n");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
      0) {
    fprintf(stderr, "Failed to set listener to re-use port\n");
    exit(EXIT_FAILURE);
  }
  if ((err = bind(listener, (struct sockaddr *)&addr, addr_size)) < 0) {
    fprintf(stderr, "Failed to bind listener to port %d\n", args.port);
    close(listener);
    exit(EXIT_FAILURE);
  }
  if ((err = listen(listener, 5)) < 0) {
    fprintf(stderr, "Failed to listen on port %d\n", args.port);
    close(listener);
    exit(EXIT_FAILURE);
  }
  printf("Listening on port %d\n", args.port);

  while (1) {
    stream =
        accept(listener, (struct sockaddr *)&addr, (socklen_t *)&addr_size);
    if (stream < 0) {
      fprintf(stderr, "Failed to accept incoming connection\n");
      close(listener);
      exit(EXIT_FAILURE);
    }

    if (stream_handler(stream) != 0) {
      goto shutdown;
    }
  }

shutdown:
  if (stream) {
    close(stream);
  }
  if (listener) {
    close(listener);
  }
  return 0;
}
