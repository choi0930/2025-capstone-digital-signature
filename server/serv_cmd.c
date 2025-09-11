#include "common.h"

int clnt_put(int client_fd, char *buffer, char *command, EVP_PKEY *pub_key){
    int check, fd, file_len, bytes_left, file_size, total_len= 0;
    int success = 1;
    size_t sign_len;
    char file_data[BUFFER_SIZE], filename[256], file_buf[BUFFER_SIZE], sign_buff[100], full_path[BUFFER_SIZE];

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