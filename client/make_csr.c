#include "common.h"

EVP_PKEY *get_key(){ //private key
    FILE *fp = fopen("./client_key/ec_priv_key.pem", "r");
    
    if(!fp){
        perror("비밀키 파일 열기 실패");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey){
        printf("비밀키 로딩 실패");
        return NULL;
    }

    return pkey;
}

X509_REQ *generate_csr(){ //csr 생성
    EVP_PKEY *pkey = get_key();
    int num = 0;
    char text_buf[256];
    if(pkey == NULL){
        printf("key -> NULL\n");
        return NULL;
    }

    X509_REQ *req = X509_REQ_new();

    X509_NAME *name = X509_NAME_new();
    char *arr[] = {"C", "ST", "L", "O", "OU", "CN"};
    char *q[] = {"Country Name (2 letter code) [AU] : ", "State or Province Name(full name) [Some-state] : ", "Locality Name (eg, city) : "
    ,"Organization Name (eg, company) : ", "Organizational Unit Name (eg, section) : ", "Common Name (e.g. server FQDN or YOUR name) : "};
   
    while(1){
        memset(text_buf, 0, 256);

        printf("%s", q[num]);
        
        fgets(text_buf, sizeof(text_buf), stdin);
        text_buf[strcspn(text_buf, "\n")] = 0;
        
        if(num == 0){
            if(strlen(text_buf) > 2){
                printf("Code is long");
                continue;
            }
        }
        
        X509_NAME_add_entry_by_txt(name, arr[num], MBSTRING_ASC, (unsigned char *)text_buf, -1, -1, 0);
        //printf("check field : %d          %s          %s\n", num, arr[num],text_buf);
        if(num == 5){
            break;
        }
        num++;
    }
    
    X509_REQ_set_subject_name(req, name);

    X509_REQ_set_pubkey(req, pkey);

    X509_REQ_sign(req, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);
    return req;

}

int send_csr(int sockfd){//csr요청 생성
    
    uint32_t len;
    X509_REQ *req = generate_csr();

    //BIO를 이용해 PEM 형식으로 메모리에 쓰기
    BIO *bio = BIO_new(BIO_s_mem());
    if(!PEM_write_bio_X509_REQ(bio, req)){
        fprintf(stderr, "x509 REQ -> PEM 변환 실패");
        X509_REQ_free(req);
        BIO_free(bio);
        return -13;    
    }

    //BIO 버퍼에서 데이터 추출
    char *csr_pem;
    long csr_len = BIO_get_mem_data(bio, &csr_pem);

    len = htonl(csr_len);
    send(sockfd, &len, sizeof(len), 0); //csr요청 길이 전송
    printf("csr요청 길이: %lu\n", csr_len);

    send(sockfd, csr_pem, csr_len, 0); //csr요청 전송
    //fwrite(csr_pem, 1, csr_len, stdout); //csr출력

    BIO_free(bio);
    X509_REQ_free(req);
   
    return 0;
}

int save_cert(X509 *cert){//인증서 저장
    FILE *fp = fopen("./client_key/client_cert.pem", "w");    
    if(fp){
        PEM_write_X509(fp, cert);
        fclose(fp);
        X509_free(cert);
        printf("인증서 저장 완료\n");
      
    }else{
        perror("fopen실패\n");
        X509_free(cert);
        
    }
}
