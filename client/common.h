#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define BUFFER_SIZE 512
#define MAXLINE 256
#define MdName EVP_sha256()

int print_ls();
int send_cert(int sockfd);
int client_to_server(int sockfd);
int ecdsa_sign(char *file_buf, int len, unsigned char **sign, size_t *sign_len);
int cert_get_pubkey(int sockfd, EVP_PKEY **pkey);
int save_cert(X509 *cert);

typedef struct {
    int sign_len;
    int file_len;
    int total_len;
}Length_Info;
