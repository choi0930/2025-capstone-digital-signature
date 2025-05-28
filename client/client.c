//client.c
#include "common.h"

int main() {
    struct stat obj;
    int sockfd, fd, file_size, status;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE], filename[MAXLINE], buf[BUFFER_SIZE], file_buf[BUFFER_SIZE];

    // 1. 소켓 생성
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){perror("socket"); exit(1);}

    // 2. 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
	inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 3. 서버에 연결
    if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("connect"); close(sockfd); exit(1);}
    printf("서버에 연결됨\n");

    // 4. 데이터 송수신
    while(1){
        printf("명령어 입력 [put, exit](종료: exit): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;  

        if(strcmp(buffer, "exit") == 0){ //exit 명령어
			send(sockfd, buffer, 5, 0);
			printf("연결 종료\n");
			break;
		}	
        else if(strcmp(buffer, "put") == 0){ //put 명령어
            unsigned char *signOut;
            size_t signOutLen;
            int bytes_send, total_len = 0;

            printf("업로드 할 파일명을 입력해주세요 :");
            if(fgets(filename, sizeof(filename), stdin) == NULL){
		    	printf("입력 오류!\n");
		    	continue;
	    	}
            filename[strcspn(filename, "\n")] = 0;  // 엔터 제거
            
            printf("filename: %s\n", filename);
            if(strlen(filename) == 0){
                printf("파일명이 비어있습니다. 다시 입력해주세요.\n");
                continue;
            }
            
            if((fd = open(filename, O_RDONLY)) == -1){//파일 open
                printf("파일이 없습니다.\n");
                continue;
            }

            strcpy(buf, "put ");
            strcat(buf, filename);
            
            //printf("명령어 조합 완료: %s\n", buf); 
            //printf("명령어 전송 시작\n");
            send(sockfd, buf, BUFFER_SIZE, 0);//명령어 전송
            
            //파일 크기 
            stat(filename, &obj);
            file_size = obj.st_size;	//stat 명령를 통해 파일 사이즈 받기
            printf("업로드 파일 크기 : %d\n", file_size);

            send(sockfd, &file_size, sizeof(int), 0); //파일 크기 전송

            printf("========[업로드 시작]========\n");
            printf("\n");
            memset(file_buf, 0x00, BUFFER_SIZE);
            
            while((bytes_send = read(fd, file_buf, BUFFER_SIZE)) >0){
                LengthInfo info; //파일 길이, 서명길이, 총길이 데이터를 저장할 구조체 선언
                signOut = NULL;
                signOutLen = 0;
               
                //printf("서명시작\n");
                ecdsa_sign(file_buf, bytes_send, &signOut, &signOutLen); //서명 동작
                
                //서명길이+자른 파일길이
                total_len = (int)signOutLen + bytes_send;

                info.signOutLen = (int)signOutLen;
                info.fileLen = bytes_send;
                info.totalLen = total_len;

                send(sockfd, &info, sizeof(LengthInfo), 0); //파일 길이, 서명길이, 총길이 데이터를 담은 구조체 send

                //전송할 파일크기 + 디지털 서명 길이 
                printf("    파일 길이: (%d) || 디지털 서명 길이: (%zu)\n", bytes_send, signOutLen);
                printf("    총 패킷 길이 : %d\n", total_len);

                //전송용 버퍼 동적 생성
                unsigned char *send_buf = (unsigned char *)malloc(total_len);
                if(send_buf == NULL) {
                    perror("malloc failed");
                    status = 0;
                    break;
                }

                //데이터 결합 (파일데이터 + 디지털 서명)
                memcpy(send_buf, file_buf, bytes_send);
                memcpy(send_buf+bytes_send, signOut, signOutLen);
                
                int sent_bytes = send(sockfd, send_buf, total_len, 0);
                if(sent_bytes != total_len){
                    perror("send failed");
                    status = 0;
                    free(send_buf);
                    break;
                }
                printf("\n");
                printf("----------------------------\n");
                free(send_buf);
                
            }
            close(fd);
            printf("\n");
            
            recv(sockfd, &status, sizeof(int), 0);	//서버에서 받았는지 확인 메세지 수신
            if(status){//업로드 성공여부 판단
                printf("========[업로드 완료]========\n");
            }else{
                printf("========[업로드 실패]========\n");
            }
        }//end put  
	}
    //종료
    close(sockfd);
    return 0;
}

