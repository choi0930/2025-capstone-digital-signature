//server
#include "common.h"

#define PORT 12345
//#define SERVER_IP "127.0.0.1"
int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
	char client_ip[INET_ADDRSTRLEN];
    socklen_t client_len;
	char buffer[BUFFER_SIZE], command[5];

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
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    	printf("[%s:%d 클라이언트 연결됨]\n", client_ip, PORT);

		cert_get_pubkey(client_fd, &pub_key);
		//EVP_PKEY *pub_key = recv_pub_key(client_fd);
		send_cert(client_fd);
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
			}
			else if(strcmp(command, "put") == 0){	//put 명령어
				clnt_put(client_fd, buffer, command, pub_key);

			}else if(strcmp(command, "get") == 0){	//get 명령어
				clnt_get(client_fd, buffer, command);
			}else if(strcmp(command, "ls") == 0){
				ls(client_fd);
			}
    	}
		EVP_PKEY_free(pub_key);
	}
	
    // 7. 종료
    close(client_fd);
    close(server_fd);
    return 0;
}