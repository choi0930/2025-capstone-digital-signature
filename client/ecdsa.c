#include "common.h"

int ecdsa_sign(char *file_buf, int len, unsigned char **sign, size_t *sign_len){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    
    //개인키 가져오기
    FILE *fp = fopen("./client_key/ec_priv_key.pem", "r");
    if(!fp){
        perror("개인 키 파일 열기 실패");
        return -11;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey){
        fprintf(stderr, "개인 키 로딩 실패");
        return -12;
    }
   
    /* 키 출력
		BIO *bio = BIO_new(BIO_s_mem());
   		PEM_write_bio_PUBKEY(bio, pkey);

    	char *data;
   		 long len2 = BIO_get_mem_data(bio, &data);

    	// 문자열 출력
    	printf("%.*s", (int)len2, data);

    	BIO_free(bio);
    */

    //ctx 초기화
    if(EVP_DigestSignInit(ctx, NULL, MdName, NULL, pkey) != 1){
        fprintf(stderr, "DigestSignInit 실패");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -13;
    }
    //파일값 해싱
    EVP_DigestSignUpdate(ctx, file_buf, len);

    //서명 길이 유추 및 서명
    assert((*sign_len = (size_t)EVP_PKEY_size(pkey))); //EVP_PKEY_size -> pkey로 생성될 디지털 서명 최대 길이를 바이트 단위로 알려준다

    *sign = OPENSSL_malloc(*sign_len); //서명 길이만큼 동적 할당

    assert(EVP_DigestSignFinal(ctx, *sign, sign_len)); //EVP_DigestSignUpdate 기반으로 서명 결과를 sign에 저장 길이를 sign_len에 실제 사용된 바이트 수 반환
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}