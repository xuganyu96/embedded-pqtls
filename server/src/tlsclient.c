#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <wolfssl/ssl.h>

#define HTTP_REQUEST                                                           \
    "GET /octocat HTTP/1.1\r\n"                                                \
    "Host: api.github.com\r\n"                                                 \
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "     \
    "Gecko/20100101 Firefox/136.0\r\n"                                         \
    "Accept: application/json\r\n"                                             \
    "Connection: close\r\n\r\n"

/**
 * Establishes a TCP connection to a specified hostname and port.
 *
 * Creates a socket, resolves the hostname to an IP address,
 * and attempts to connect to the specified port on the resolved address.
 *
 * @param hostname The hostname to connect to (e.g., "example.com").
 * @param port The port number to connect to (e.g., 80 for HTTP).
 * @return int Returns the socket file descriptor on success, or -1 on failure.
 */
static int tcp_connect(const char *hostname, int port) {
    struct sockaddr_in server_addr; /* netinet/in.h */
    struct hostent *server;         /* netdb.h */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    server = gethostbyname(hostname);
    if (!server) {
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        close(sockfd); /* unistd.h */
        return -1;
    }
    return sockfd;
}

int main(void) {
    wolfSSL_Init();

    unsigned char http_rx_buf[2048];
    int rx_buf_len = 0, readlen;

    int ssl_ret, sockfd;
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "Failed to create WolfSSL context\n");
        exit(EXIT_FAILURE);
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "Failed to create SSL struct\n");
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    if ((sockfd = tcp_connect("api.github.com", 443)) < 0) {
        fprintf(stderr, "Failed to establish TCP connection\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    wolfSSL_set_fd(ssl, sockfd);
    if ((ssl_ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Connected to github.com:443\n");

    wolfSSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
    while ((readlen = wolfSSL_read(ssl, http_rx_buf + rx_buf_len,
                                   sizeof(http_rx_buf) - rx_buf_len)) > 0) {
        rx_buf_len += readlen;
    }
    http_rx_buf[rx_buf_len] = '\0';
    printf("%s\n", http_rx_buf);

    wolfSSL_shutdown(ssl);
    close(sockfd);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    wolfSSL_Cleanup();

    return 0;
}
