/* ROOT CA */
#include "common.h"

#define PORT 54321

int main() {

    int server_fd, client_fd, fd, file_size;
    struct sockaddr_in server_addr, client_addr;
	char client_ip[INET_ADDRSTRLEN];
    socklen_t client_len;
	char buffer[BUFFER_SIZE], command[5], filename[256], file_buf[BUFFER_SIZE], sign_buff[100], full_path[BUFFER_SIZE];

  	// 1. 소켓 생성
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd == -1){perror("socket"); exit(1);}

    // 2. 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; 					//inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
	server_addr.sin_addr.s_addr = INADDR_ANY;		
    server_addr.sin_port = htons(PORT);

    // 3. 바인드
    if(bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("bind"); close(server_fd); exit(1);}

    while(1){
        // 4. 리슨
    	if(listen(server_fd, 5) == -1){perror("listen"); close(server_fd);exit(1);}
    	printf("서버 대기 중...\n");

        client_len = sizeof(client_addr);
    	client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    	if(client_fd == -1){perror("accept"); close(server_fd); exit(1);}
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    	printf("[%s:%d 클라이언트 연결됨]\n", client_ip, PORT);

         //인증서 전송
        printf("----------------------------\n");
        send_cert(client_fd); 
        printf("----------------------------\n");
        printf("root_ca인증서 전송 완료\n");

        while(1){
            memset(buffer, 0, BUFFER_SIZE);
            printf("명령 대기 중...\n");

            int recv_len = recv(client_fd, buffer, BUFFER_SIZE, 0); //명령어 이름 수신
			if(recv_len <= 0){perror("recv 실패"); break;}
	
			sscanf(buffer, "%s", command);	//명령어 command에 옮김

			printf("Client Command: %s\n", command);

            if(strcmp(command, "exit") == 0){ //exit 명령어
				printf("클라이언트 연결 종료\n");
				close(client_fd); 
				break;
			}else if(strcmp(command, "request_cert") == 0){ //request cert명령어 인증서 생성 요청
                uint32_t len_net;
                char *csr_pem;
                printf("인증서 생성\n");
                recv(client_fd, &len_net, sizeof(len_net), 0); //csr요청 길이
                uint32_t len = ntohl(len_net);

                printf("csr요청 길이: %u\n", len);
                
                csr_pem = malloc(len);
                if(csr_pem == NULL){
                    perror("csr_pem malloc failed");
                    
                }
                recv(client_fd, csr_pem, len, 0); //csr요청 
                //fwrite(csr_pem, 1, len, stdout); //csr출력
                
                X509 *client_cert = sign_cert(csr_pem);

                //pem형식으로 직렬화
                BIO *bio = BIO_new(BIO_s_mem());
                PEM_write_bio_X509(bio, client_cert);

                char *pem_data;
                long pem_len = BIO_get_mem_data(bio, &pem_data);
                //인증서 길이 전송
                uint32_t net_len = htonl((uint32_t)pem_len);
                send(client_fd, &net_len, sizeof(net_len), 0);
                //인증서 데이터 전송
                send(client_fd, pem_data, pem_len, 0);

                free(csr_pem);
                
            } 
        }
    }
}