#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

//#include <openssl/encoder.h>
//#include <openssl/decoder.h>

#define BUFFER_SIZE 512
#define MAXLINE 256
#define MdName EVP_sha256()


int send_cert(int sockfd);

//int send_pub_key(int sockfd);

int ecdsa_sign(char *file_buf, int len, unsigned char **sign, size_t *sign_len);

typedef struct {
    int sign_len;
    int file_len;
    int total_len;
}Length_Info;
