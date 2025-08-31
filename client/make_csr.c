/*
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
*/
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
        
        X509_NAME_add_entry_by_txt(name, arr[num], MBSTRING_ASC, (unsigned char *)text_buf, -1, -1, 0);
        printf("check field : %d          %s          %s\n", num, arr[num],text_buf);
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
    fwrite(csr_pem, 1, csr_len, stdout); //csr출력

    BIO_free(bio);
    X509_REQ_free(req);
   
    return 0;
}

//test
int main(int argc, char *argv[]){
     struct stat obj;
    int sockfd, fd, file_size, status;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE], filename[MAXLINE], buf[BUFFER_SIZE], file_buf[BUFFER_SIZE], full_path[BUFFER_SIZE];

    // 1. 소켓 생성
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){perror("socket"); exit(1);}

    // 2. 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(54321);
	inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    // 3. 서버에 연결
    if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("connect"); close(sockfd); exit(1);}
    printf("[%s:%d 서버에 연결됨]\n", argv[1], 54321);
    while(1){
        memset(full_path, 0x00, BUFFER_SIZE);

        printf("명령어 입력 [request_cert, exit](종료: exit): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;  
        
        if(strcmp(buffer, "exit") == 0){ //exit 명령어
			send(sockfd, buffer, 5, 0);
			printf("연결 종료\n");
			break;
        /*-----------------쓸수 있는 부분------------------------------------------*/
        }else if(strcmp(buffer, "request_cert") == 0){
            uint32_t net_len;

            send(sockfd, buffer, 13, 0);
            
            send_csr(sockfd);
            
            recv(sockfd, &net_len, sizeof(net_len), MSG_WAITALL); //MSG_WAITALL -> 정확히 요청한 길이만큼 다 받을떄까지 대기 
            uint32_t pem_len = ntohl(net_len);

            char *pem_buf = malloc(pem_len+1);
            recv(sockfd, pem_buf, pem_len, MSG_WAITALL);
            pem_buf[pem_len] = '\0';

            BIO *cbio = BIO_new_mem_buf(pem_buf, pem_len);
            X509 *cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);

            if(cert){
                printf("클라이언트: 인증서 수신 성공\n");
                X509_print_fp(stdout, cert);
            }

            X509_free(cert);
            BIO_free(cbio);
            free(pem_buf);

        }
        /*------------------------------------------------------------------------*/
    }
}//test 