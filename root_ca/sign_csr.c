#include "common.h"

EVP_PKEY *get_key(){ //root_ca private key
    FILE *fp = fopen("./ca_info/ca_ec_priv_key.pem", "rb");
    
    if(!fp){
        perror("비밀키 파일 열기 실패");
        fclose(fp);
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    
    if(!pkey){
        printf("비밀키 로딩 실패\n");
        EVP_PKEY_free(pkey);
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
    
    X509 *cert = PEM_read_X509(fp_cert, NULL, NULL, NULL);
    
    if(!cert){
        printf("인증서 로딩 실패\n");
        return NULL;
    }

    fclose(fp_cert);
    return cert;
}

long read_serial(){
    FILE *fp = fopen("./ca_info/serial.txt", "r");
    long serial = 1;
    if(fp){
        if(fscanf(fp, "%ld", &serial) != 1){
            serial = 1;
        }
        fclose(fp);
    }
    
    printf("serial = %ld\n", serial);

    return serial;
}

void write_serial(long serial){
    FILE *fp = fopen("./ca_info/serial.txt", "w");
    if(!fp){
        perror("serial파일 열기 실패\n");
        return;
    }
    fprintf(fp, "%ld\n", serial);
    fclose(fp);
}

X509 *sign_cert(char* csr_pem){//클라이언트 csr요청 기반으로 인증서 생성
    X509 *ca_cert = load_certificate(); //root ca의 인증서
    EVP_PKEY *ca_pkey = get_key(); //ca 비밀키

    //csr 파싱-------------------------------------------------------
    BIO *bio = BIO_new_mem_buf(csr_pem, -1);
    if(!bio){
        perror("BIO_new_mem_buf failed");
        return NULL;
    }

    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!req){
        perror("pem_read_bio_X509_REQ failed");
        return NULL;
    }
    //---------------------------------------------------------------
    //csr 서명 검증---------------------------------------------------
    EVP_PKEY *req_pubkey= X509_REQ_get_pubkey(req); //csr요청에서 공개키 추출
    if(!req_pubkey){
        perror("X509_REQ_get_pubkey failed");
        X509_REQ_free(req);
        return NULL;
    }

    if(X509_REQ_verify(req, req_pubkey) <= 0){ //클라이언트의 서명검증
        fprintf(stderr,"CSR signature verification failed!\n");
        X509_REQ_free(req);
        EVP_PKEY_free(req_pubkey);
        return NULL;
    }
    printf("CSR signature verified successfully\n");
    //---------------------------------------------------------------

    X509 *client_cert = X509_new(); //새 인증서 객체

    long serial = read_serial(); //일렬번호 불러오기

    ASN1_INTEGER_set(X509_get_serialNumber(client_cert), serial); //일렬번호 설정

    write_serial(serial+1);//다음 인증서 발급에 사용할 일렬번호 저장

    X509_gmtime_adj(X509_get_notBefore(client_cert), 0); //유효기간 설정
    X509_gmtime_adj(X509_get_notAfter(client_cert), 31516000L); //1년

    X509_set_issuer_name(client_cert, X509_get_subject_name(ca_cert));//issuer 인증서 발급자 설정

    X509_NAME *subj = X509_REQ_get_subject_name(req); //subject (클라이언트 CSR에서 추출)
    X509_set_subject_name(client_cert, subj);

    X509_set_pubkey(client_cert, req_pubkey); //client 공개키 설정
    EVP_PKEY_free(req_pubkey);

    if(!X509_sign(client_cert, ca_pkey, EVP_sha256())){
        perror("X509_sign failed");
        EVP_PKEY_free(ca_pkey);
        X509_free(client_cert);
        X509_REQ_free(req);
        return NULL;
    }

    EVP_PKEY_free(ca_pkey);
    X509_REQ_free(req);
    X509_print_fp(stdout, client_cert);
    return client_cert;    
}