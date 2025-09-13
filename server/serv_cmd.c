#include "common.h"

int clnt_put(int client_fd, char *buffer, char *command, EVP_PKEY *pub_key){
    int check, fd, file_len, bytes_left, file_size, total_len= 0;
    int success = 1;
    size_t sign_len;
    char file_data[BUFFER_SIZE], filename[MAXLINE], file_buf[BUFFER_SIZE], sign_buff[100], full_path[BUFFER_SIZE];

    memset(file_data, 0x00, BUFFER_SIZE);

    sscanf(buffer + strlen(command), "%s", filename); //command 이후 filename에 포인팅
    printf("filename: %s\n", filename);

    while(1){
        snprintf(full_path, sizeof(full_path), "./file/%s", filename);
        fd = open(full_path, O_CREAT | O_EXCL | O_WRONLY, 0666);
        if(fd == -1){
            sprintf(filename + strlen(filename), "_1");}
        else
            break;
    }

    printf("\n=======[데이터 수신 시작]=======\n");
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
            perror("파일 쓰기 오류 발생: \n");
            success = 0;
            free(recv_buf);
            break;
        }

        bytes_left -= file_len; //수신한 파일의 크기에서 recv한 데이터 크기만큼 빼서 남은 파일 크기 계산
        free(recv_buf);

        printf("\n");
        printf("--------------------------------\n");
        printf("\n");
        cnt++;
    }
    
    if(file_len < 0){
        perror("파일 수신 오류 발생: \n");
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
    printf("=======[데이터 수신 끝]=========\n\n");
}

int clnt_get(int client_fd, char *buffer, char  *command){
    struct stat obj;
    size_t sign_len;
    int fd, status, file_size, bytes_send, total_len;
    char file_data[BUFFER_SIZE], filename[MAXLINE], full_path[BUFFER_SIZE], file_buf[BUFFER_SIZE];
    unsigned char *sign;
    total_len, bytes_send, status = 0;

    memset(file_data, 0x00, BUFFER_SIZE);
    memset(full_path, 0x00, BUFFER_SIZE);
    
    sscanf(buffer + strlen(command), "%s", filename); //command 이후 filename에 포인팅
    printf("filename: %s\n", filename); //확인용 나중에 주석처리

    snprintf(full_path, sizeof(full_path), "./file/%s", filename);
    fd = open(full_path, O_RDONLY);

    if(fd == -1){//파일 존재 여부
        send(client_fd, &status, sizeof(int), 0); //요구한 파일이 없을 경우
        return -1;
    }else{
        status = 1;
        send(client_fd, &status, sizeof(int), 0);
    }

    stat(full_path, &obj);   //파일 크기
    file_size = obj.st_size;	//stat 명령를 통해 파일 사이즈 받기
    printf("File_size: %d byte\n\n", file_size); //확인용

    send(client_fd, &file_size, sizeof(int), 0); //파일 크기 전송

    while((bytes_send = read(fd, file_buf, BUFFER_SIZE)) >0){
        Length_Info info; //파일 길이, 서명길이, 총길이 데이터를 저장할 구조체 선언
        sign = NULL;
        sign_len = 0;

        ecdsa_sign(file_buf, bytes_send, &sign, &sign_len); //서명 동작

        total_len = (int)sign_len + bytes_send;

        info.sign_len = (int)sign_len;
        info.file_len = bytes_send;
        info.total_len = total_len;

        send(client_fd, &info, sizeof(Length_Info), 0); //파일 길이, 서명길이, 총길이 데이터를 담은 구조체 send

        unsigned char *send_buf = (unsigned char *)malloc(total_len);
        if(send_buf == NULL) {
            perror("malloc failed");
            status = 0;
            break;
        }

        memcpy(send_buf, file_buf, bytes_send);
        memcpy(send_buf+bytes_send, sign, sign_len);
        
        int sent_bytes = send(client_fd, send_buf, total_len, 0);
        if(sent_bytes != total_len){
            perror("send failed");
            status = 0;
            free(send_buf);
            break;
        }
        free(send_buf);
    }
    close(fd);

    recv(client_fd, &status, sizeof(int), 0);	//서버에서 받았는지 확인 메세지 수신
    if(status){//업로드 성공여부 판단
        printf("========[업로드 완료]========\n\n");
    }else{
        printf("========[업로드 실패]========\n\n");
    }
}

int ls(int client_fd){
    char filename[MAXLINE], full_path[MAXLINE];
	DIR *d;
	struct dirent *dir;
	struct stat file_info;
	int status = 0;
    
	d = opendir("./file");
	if(d){
	    while((dir = readdir(d)) != NULL){
            memset(filename, 0x00, MAXLINE);
			memset(full_path, 0x00, MAXLINE);

			//printf("%s\n", dir -> d_name);
			snprintf(full_path, MAXLINE+10, "./file/%s", dir->d_name);
			lstat(full_path, &file_info);
						
			if(S_ISREG(file_info.st_mode)){ //파일만 분류
                status = 1;
                send(client_fd, &status, sizeof(int), 0); //파일명 있는지 체크여부 보내줌

                size_t max_name = sizeof(filename)-2;
                size_t namelen = strnlen(dir->d_name, max_name);

				printf("파일이름: %s\n", dir->d_name);
							
				int len = snprintf(filename, sizeof(filename), "%.*s\r", (int)namelen, dir->d_name);
				//printf("길이 : %d\n",len);
				//printf("파일명 : %s\n",filename);

				send(client_fd, filename, sizeof(filename), 0);
			}
			status = 0;			
		}
        send(client_fd, &status, sizeof(int), 0);
	    
		closedir(d);
	}

}
    