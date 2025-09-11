#include "common.h"

int clnt_to_serv(int sockfd){
    char buffer[BUFFER_SIZE];

     //인증서 전송
    printf("----------------------------\n");
    send_cert(sockfd);
    printf("----------------------------\n");

    // 4. 데이터 송수신
    while(1){
        printf("명령어 입력 [put, get, file_ls, exit](종료: exit): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if(strcmp(buffer, "exit") == 0){ //exit 명령어
			send(sockfd, buffer, 5, 0);
			printf("연결 종료\n");
			break;
		}else if(strcmp(buffer, "file_ls") == 0){ //file_ls명령어
            print_ls();
        }else if(strcmp(buffer, "put") == 0){ //put 명령어
            if(put_file(sockfd) == -1){
                continue;
            }
        }else if(strcmp(buffer, "get") == 0){ //put 명령어
            
        }
	}
    return sockfd;
}