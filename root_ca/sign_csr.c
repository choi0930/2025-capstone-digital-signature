#include "common.h"

EVP_PKEY *get_key(){ //root_ca private key
    FILE *fp = fopen("./ca_info/ca_ec_priv_key.pem", "rb");
    
    if(!fp){
        perror("비밀키 파일 열기 실패");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    
    if(!pkey){
        printf("비밀키 로딩 실패"\n);
        return NULL;
    }

    fclose(fp);
    return pkey;
}

X509 *load_certificate(){//open ca cert
    FILE *fp_cert = fopen("./ca_info/ca_cert.pem", "rb");

    if(!fp_cert){
        perror("인증서 파일 열기 실패");
        return NULL;
    }
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    
    if(!cert){
        printf("인증서 로딩 실패\n");
        return NULL;
    }

    fclose(fp_cert);
    return cert;
}

X509 *sign_cert(char* csr_pem){//클라이언트 csr요청 기반으로 인증서 생성
    X509 *ca_cert = load_certificate(); //root ca의 인증서
    EVP_PKEY *pkey = get_key(); //ca 비밀키

    BIO *bio = BIO_new_mem_buf(csr_pem, -1);
    if(!bio){
        perror("BIO_new_mem_buf failed");
        return null;
    }

    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!req){
        perror("pem_read_bio_X509_REQ failed");
        return null;
    }


    X509 *client_cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(client_cert), 1);
    X509_gmtime_adj(X509_get_notBfter(client_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(client_cert), 31516000L);

    


    
}