#include "common.h"
 
int client_to_server(int sockfd){
    struct stat obj;
    int fd, file_size, status;
    char buffer[BUFFER_SIZE], filename[MAXLINE], buf[BUFFER_SIZE], file_buf[BUFFER_SIZE], full_path[BUFFER_SIZE];

     //인증서 전송
    printf("----------------------------\n");
    send_cert(sockfd); 
    printf("----------------------------\n");

    // 4. 데이터 송수신
    while(1){
        memset(full_path, 0x00, BUFFER_SIZE);

        printf("명령어 입력 [put, pull, file_ls, exit](종료: exit): ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;  

        if(strcmp(buffer, "exit") == 0){ //exit 명령어
			send(sockfd, buffer, 5, 0);
			printf("연결 종료\n");
			break;
		}else if(strcmp(buffer, "file_ls") == 0){ //file_ls명령어
            
            print_ls();

        }else if(strcmp(buffer, "put") == 0){ //put 명령어
            unsigned char *sign;
            size_t sign_len;
            int bytes_send, total_len = 0;
            
            print_ls();
           
            printf("업로드 할 파일명을 입력해주세요 :");
            if(fgets(filename, sizeof(filename), stdin) == NULL){
		    	printf("입력 오류!\n");
		    	continue;
	    	}
            printf("\n");

            filename[strcspn(filename, "\n")] = 0;  // 엔터 제거
            
            printf("File_name: %s\n", filename);
            if(strlen(filename) == 0){
                printf("파일명이 비어있습니다. 다시 입력해주세요.\n");
                continue;
            }
            snprintf(full_path, sizeof(full_path), "./file/%s", filename);

            if((fd = open(full_path, O_RDONLY)) == -1){//파일 open
                printf("파일이 없습니다.\n");
                continue;
            }

            strcpy(buf, "put ");    //명령어
            strcat(buf, filename);  //명령어 + 파일명명
            
            //printf("명령어 조합 완료: %s\n", buf); 
            //printf("명령어 전송 시작\n");
            send(sockfd, buf, BUFFER_SIZE, 0);//명령어 전송
            
            stat(full_path, &obj);   //파일 크기
            file_size = obj.st_size;	//stat 명령를 통해 파일 사이즈 받기
            printf("File_size: %d byte\n\n", file_size);

            send(sockfd, &file_size, sizeof(int), 0); //파일 크기 전송

            printf("========[업로드 시작]========\n");
            printf("\n");
            memset(file_buf, 0x00, BUFFER_SIZE);

            int cnt = 1;
            while((bytes_send = read(fd, file_buf, BUFFER_SIZE)) >0){
                if(cnt != 1)
                    printf("-----------------------------\n\n");
                printf("Fragment %d\n", cnt);
                Length_Info info; //파일 길이, 서명길이, 총길이 데이터를 저장할 구조체 선언
                sign = NULL;
                sign_len = 0;
               
                //printf("서명시작\n");
                ecdsa_sign(file_buf, bytes_send, &sign, &sign_len); //서명 동작
                
                //서명길이+자른 파일길이
                total_len = (int)sign_len + bytes_send;

                info.sign_len = (int)sign_len;
                info.file_len = bytes_send;
                info.total_len = total_len;

                send(sockfd, &info, sizeof(Length_Info), 0); //파일 길이, 서명길이, 총길이 데이터를 담은 구조체 send

                //전송할 파일크기 + 디지털 서명 길이 
                printf("\t파일 길이: (%d) || 디지털 서명 길이: (%zu)\n", bytes_send, sign_len);
                printf("\t총 패킷 길이: %d\n\n", total_len);

                //전송용 버퍼 동적 생성
                unsigned char *send_buf = (unsigned char *)malloc(total_len);
                if(send_buf == NULL) {
                    perror("malloc failed");
                    status = 0;
                    break;
                }

                //데이터 결합 (파일데이터 + 디지털 서명)
                memcpy(send_buf, file_buf, bytes_send);
                memcpy(send_buf+bytes_send, sign, sign_len);
                
                int sent_bytes = send(sockfd, send_buf, total_len, 0);
                if(sent_bytes != total_len){
                    perror("send failed");
                    status = 0;
                    free(send_buf);
                    break;
                }
                free(send_buf);
                cnt++;
            }
            close(fd);
            
            recv(sockfd, &status, sizeof(int), 0);	//서버에서 받았는지 확인 메세지 수신
            if(status){//업로드 성공여부 판단
                printf("========[업로드 완료]========\n\n");
            }else{
                printf("========[업로드 실패]========\n\n");
            }
        }//end put
        else if(strcmp(buffer, "pull") == 0){ //pull
            memset(filename, 0x00, MAXLINE);
            char test[512];
            send(sockfd, buffer, 5, 0);
            int n = 0;
            while((n = recv(sockfd, test, sizeof(test)-1, 0)) > 0){
                test[n] = '\n';
                printf("%s\n", test);
            }
/*
            while(1){
                recv(sockfd, filename, 256, 0);
               
                printf("파일이름: %s\n", filename);
                if(strcmp(filename, "END"))
                    break;
            }
*/
        }//end pull
	}
    
    return sockfd;

 }