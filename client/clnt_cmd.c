#include "common.h"

int put_file(int sockfd){
    struct stat obj;
    size_t sign_len;
    int fd, file_size, status;
    int bytes_send, total_len = 0;
    char filename[MAXLINE], file_buf[BUFFER_SIZE], buf[BUFFER_SIZE], full_path[BUFFER_SIZE];
    unsigned char *sign;

    memset(full_path, 0x00, BUFFER_SIZE);

    print_ls(); //파일 확인(현재 'file' 폴더만 확인 가능)
    
    //파일명 입력 start
    printf("업로드 할 파일명을 입력해주세요 :");
    if(fgets(filename, sizeof(filename), stdin) == NULL){
        printf("입력 오류!\n");
        return -1;;
    }
    printf("\n");

    filename[strcspn(filename, "\n")] = 0;  // 엔터 제거
    
    printf("File_name: %s\n", filename);
    if(strlen(filename) == 0){
        printf("파일명이 비어있습니다. 다시 입력해주세요.\n");
        return -1;
    }
    snprintf(full_path, sizeof(full_path), "./file/%s", filename);
    //파일명 입력 end

    if((fd = open(full_path, O_RDONLY)) == -1){//파일 open
        printf("파일이 없습니다.\n");
        return -1;
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
}

int get_file(int sockfd, EVP_PKEY *pub_key){
    int fd, check, check_status, file_size, bytes_left, sign_len, total_len, file_len= 0;
    int success = 1;
    char filename[MAXLINE], full_path[BUFFER_SIZE], buf[BUFFER_SIZE], file_buf[BUFFER_SIZE], sign_buf[100];
    
    memset(full_path, 0x00, BUFFER_SIZE);

    printf("다운 할 파일명을 입력해주세요 :");
    if(fgets(filename, sizeof(filename), stdin) == NULL){
        printf("입력 오류!\n");
        return -1;;
    }
    printf("\n");

    filename[strcspn(filename, "\n")] = 0;  // 엔터 제거

    printf("File_name: %s\n", filename);//확인용
    if(strlen(filename) == 0){
        printf("파일명이 비어있습니다. 다시 입력해주세요.\n");
        return -1;
    }
    strcpy(buf, "get ");    //명령어
    strcat(buf, filename);  //명령어 + 파일명명
    
    //printf("명령어 조합 완료: %s\n", buf);
    //printf("명령어 전송 시작\n");
    send(sockfd, buf, BUFFER_SIZE, 0);//명령어 전송

    recv(sockfd, &check_status, sizeof(int), 0); //서버에 입력한 파일이 있는지 확인

    if(check_status == 0){
        printf("입력하신 파일이 없습니다\n");
        return -1;
    }

    while(1){//파일 오픈
        snprintf(full_path, sizeof(full_path), "./file/%s", filename);
        fd = open(full_path, O_CREAT | O_EXCL | O_WRONLY, 0666);
        if(fd == -1){
            sprintf(filename + strlen(filename), "_1");}
        else
            break;
    }

    recv(sockfd, &file_size, sizeof(int), 0);	//파일의 전체 크기 수신
    bytes_left = file_size;

    while(bytes_left >0){
        Length_Info info;
        memset(file_buf, 0x00, BUFFER_SIZE);
        memset(sign_buf, 0x00, 100);
        sign_len = 0;
        total_len = 0;

        recv(sockfd, &info, sizeof(Length_Info), 0); //파일 길이, 서명길이, 총길이 데이터를 담은 구조체 recv

        file_len = info.file_len;
        sign_len = info.sign_len;
        total_len = info.total_len;

        //printf("\t파일 길이: (%d) || 디지털 서명 길이: (%zu)\n", file_len, sign_len);
        //printf("\t총 패킷 길이: %d\n", total_len);

        //수신용 버퍼 동적 생성
        unsigned char *recv_buf = (unsigned char *)malloc(total_len);
        if(recv_buf == NULL) {
            perror("malloc failed");
            success =0;
            break;
        }

        int recv_bytes = recv(sockfd, recv_buf, total_len, 0); //자른 파일 데이터 + 데이터에 대한 서명 값 recv
        if(recv_bytes != total_len){
            perror("send failed");
            success =0;
            break;
        }

        memcpy(file_buf, recv_buf, file_len);
        memcpy(sign_buf, recv_buf + file_len, sign_len);

        printf("\n");
        printf("[서명 검증]--->");

        if(ecdsa_verify(file_buf, file_len, sign_buf, sign_len, pub_key)){ //서명 검증
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

    send(sockfd, &success, sizeof(int), 0);		//write 성공 여부를 client 송신

    return 1;
}