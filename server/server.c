//server

#include "common.h"

#define PORT 12345
#define BUFFER_SIZE 512
//#define SERVER_IP "127.0.0.1"
int main() {
    int server_fd, client_fd, fd, file_size;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
	char buffer[BUFFER_SIZE], command[5], filename[256], file_buf[BUFFER_SIZE], sign_buff[100];

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
		EVP_PKEY *pub_key = NULL;
    	// 4. 리슨
    	if(listen(server_fd, 5) == -1){perror("listen"); close(server_fd);exit(1);}
    	printf("서버 대기 중...\n");

    	// 5. 연결 수락
    	client_len = sizeof(client_addr);
    	client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    	if(client_fd == -1){perror("accept"); close(server_fd); exit(1);}
    	printf("클라이언트 연결됨\n");

		cert_get_pubkey(client_fd, &pub_key);

		while(1){
			memset(buffer, 0, BUFFER_SIZE);
			printf("명령 대기 중...\n");
		
			int recv_len = recv(client_fd, buffer, BUFFER_SIZE, 0); //명령어 이름 수신
			if(recv_len <= 0){perror("recv 실패"); break;}
	
			sscanf(buffer, "%s", command);	//명령어 command에 옮김

			printf("클라이언트로부터 명령 수신: %s\n", command);
			
			if(strcmp(command, "exit") == 0){ //exit 명령어
				printf("클라이언트 연결 종료\n");
				close(client_fd);
				break;
			}
			else if(strcmp(command, "put") == 0){	//put 명령어
				int check, file_len, bytes_left, total_len= 0;
				int success = 1;
				size_t sign_len;
				char file_data[BUFFER_SIZE];
				memset(file_data, 0x00, BUFFER_SIZE);			

				sscanf(buffer + strlen(command), "%s", filename); //command 이후 filename에 포인팅
				printf("filename: %s\n", filename);

				while(1){
					fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0666);	
					if(fd == -1){
						sprintf(filename + strlen(filename), "_1");}
					else
						break;
				}

				printf("=======[데이터 수신 시작]=======\n");
				printf("\n");

				recv(client_fd, &file_size, sizeof(int), 0);	//파일의 전체 크기 수신
				bytes_left = file_size;
				
				int cnt = 1;
				while(bytes_left > 0){ //클라이언트에서 받은 파일 크기만큼 반복문수행
					printf("Fragment %d\n", cnt);
					Length_Info info;
					memset(file_buf, 0x00, BUFFER_SIZE);
					memset(sign_buff, 0x00, 100);
                	sign_len = 0;
					total_len = 0;

					recv(client_fd, &info, sizeof(Length_Info), 0); //파일 길이, 서명길이, 총길이 데이터를 담은 구조체 recv
					
					file_len = info.file_len;
					sign_len = info.sign_len;
					total_len = info.total_len;

					printf("\t파일 길이: (%d) || 디지털 서명 길이: (%zu)\n", file_len, sign_len);
                    printf("\t총 패킷 길이: %d\n", total_len);

					//수신용 버퍼 동적 생성
                	unsigned char *recv_buf = (unsigned char *)malloc(total_len);
                	if(recv_buf == NULL) {
                   		perror("malloc failed");
                    	success =0;
                    	break;
                	}

					int recv_bytes = recv(client_fd, recv_buf, total_len, 0); //자른 파일 데이터 + 데이터에 대한 서명 값 recv	
					if(recv_bytes != total_len){
                    	perror("send failed");
                   		success =0;
                    	break;
                	}

					memcpy(file_buf, recv_buf, file_len);
					memcpy(sign_buff, recv_buf + file_len, sign_len);

					printf("\n");
					printf("[서명 검증]--->");

					if(ecdsa_verify(file_buf, file_len, sign_buff, sign_len, pub_key)){ //서명 검증
						printf("\tverify success\n");
						check = write(fd, file_buf, file_len);	//검증 성공시 파일 데이터 write			
					}else{
						printf("\tverify fail\n");
						success = 0;
						free(recv_buf);
						break;
					}
		
					if(check < 0){
						perror("파일 쓰기 오류 발생: ");
						success = 0;
						free(recv_buf);
						break;
					}

					bytes_left -= file_len; //수신한 파일의 크기에서 recv한 데이터 크기만큼 빼서 남은 파일 크기 계산
					free(recv_buf);

					printf("\n");
					printf("-------------------------------\n");
					printf("\n");
					cnt++;
				}
				
				if(file_len < 0){
					perror("파일 수신 오류 발생: ");
					success = 0;
				}

				close(fd);
				
				if(success){
					printf("%s save success\n", filename);
				}else{
					printf("%s save fail\n", filename);
					remove(filename); //검증이 실패했거나 파일 write, 수신에 오류가 발생시 파일 삭제
				}

				send(client_fd, &success, sizeof(int), 0);		//write 성공 여부를 client 송신

				printf("\n");
				printf("=======[데이터 수신 끝]=======\n");
			}
    	}	
		EVP_PKEY_free(pub_key);
	}
	
    // 7. 종료
    close(client_fd);
    close(server_fd);
    return 0;
}