#include "common.h"

int ecdsa_verify(char *file_buf, int len, unsigned char *sign, size_t sign_len, EVP_PKEY *pkey){
    int ret = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    /*
    //공개키 가져오기
    FILE *fp = fopen("ec_public_key.pem", "r");
    if(!fp){
        perror("공개 키 파일 열기 실패");
        return -11;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey){
        fprintf(stderr, "공개 키 로딩 실패");
        return -12;
    }
*/
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new 실패\n");
        return -1;
    }

    if (!pkey) {
        fprintf(stderr, "공개키가 NULL입니다\n");
        EVP_MD_CTX_free(ctx);
        return -2;
    }

    //ctx 초기화
    if(EVP_DigestVerifyInit(ctx, NULL, MdName, NULL, pkey) != 1){
        fprintf(stderr, "DigestVerifyInit 실패");
        EVP_MD_CTX_free(ctx);
        
        return -13;
    }

    EVP_DigestVerifyUpdate(ctx, file_buf, len);

    ret = EVP_DigestVerifyFinal(ctx, sign, sign_len);
    EVP_MD_CTX_free(ctx);

    return ret;
}