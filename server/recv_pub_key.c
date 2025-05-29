#include "common.h"

EVP_PKEY* recv_pub_key(int client_fd){
   long pem_len = 0;
    int n = recv(client_fd, &pem_len, sizeof(long), 0);
    if (n <= 0) {
        perror("길이 수신 실패");
        return NULL;
    }
    
    char *pem_data = malloc(pem_len + 1);
    if (!pem_data) {
        perror("메모리 할당 실패");
        return NULL;
    }

    int total = 0;
    while (total < pem_len) {
        int r = recv(client_fd, pem_data + total, pem_len - total, 0);
        if (r <= 0) {
            perror("공개키 본문 수신 실패");
            free(pem_data);
            return NULL;
        }
        total += r;
    }
    pem_data[pem_len] = '\0'; // 안전을 위해 널 종료

    BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "공개 키 파싱 실패\n");
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    free(pem_data);
    return pkey;
}