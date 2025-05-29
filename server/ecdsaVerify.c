#include "common.h"

int ecdsa_verify(char *file_buf, int len, unsigned char *sign, size_t sign_len, EVP_PKEY *pkey){

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
    BIO *bio = BIO_new(BIO_s_mem());
   		 PEM_write_bio_PUBKEY(bio, pkey);

    	char *data;
   		 long len2 = BIO_get_mem_data(bio, &data);

    	// 문자열 출력
    	printf("2번째 : %.*s", (int)len2, data);

    	BIO_free(bio);
    //ctx 초기화
    if(EVP_DigestVerifyInit(ctx, NULL, MdName, NULL, pkey) != 1){
        fprintf(stderr, "DigestVerifyInit 실패");
        EVP_MD_CTX_free(ctx);
       
        return -13;
    }

    EVP_DigestVerifyUpdate(ctx, file_buf, len);

    return(EVP_DigestVerifyFinal(ctx, sign, sign_len));

    EVP_MD_CTX_free(ctx);
}