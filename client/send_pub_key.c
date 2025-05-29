#include "common.h"

int send_pub_key(int sockfd){
    
    FILE *fp = fopen("ec_public_key.pem", "r");
    
    if(!fp){
        perror("공개 키 파일 열기 실패");
        return -5;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey){
        fprintf(stderr, "공개 키 로딩 실패");
        return -12;
    }
    // BIO를 이용해 PEM 형식으로 메모리에 쓰기
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        fprintf(stderr, "PEM 변환 실패\n");
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -13;
    }

    // BIO 버퍼에서 데이터 추출
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    
    send(sockfd, &pem_len, sizeof(long), 0);
    // 전송
    if (send(sockfd, pem_data, pem_len, 0) != pem_len) {
        perror("공개 키 전송 실패");
    }

    EVP_PKEY_free(pkey);
    BIO_free(bio);
}