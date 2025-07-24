#include <stdio.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

int main(void) {
    printf("你好，🌍!\n");
    wolfSSL_Init();
    return 0;
}
