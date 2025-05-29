#include "common.h"

int send_pubkey(int sockfd) {
    FILE *fp = fopen("./client_key/pubkey.pem", "r");
    if (!fp) {
        perror("공개키 파일 open 실패");
        return -14;
    }

    // 파일 크기 구하기
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);

    if (filesize <= 0) {
        fprintf(stderr, "공개키 파일 크기 오류\n");
        fclose(fp);
        return -15;
    }

    // PEM 텍스트 읽기
    char *buf = malloc(filesize + 1);
    if (!buf) {
        fprintf(stderr, "메모리 할당 실패\n");
        fclose(fp);
        return -16;
    }

    size_t read_len = fread(buf, 1, filesize, fp);
    fclose(fp);
    buf[read_len] = '\0'; // 널 종료자

    if (read_len != filesize) {
        fprintf(stderr, "공개키 파일 읽기 실패\n");
        free(buf);
        return -17;
    }

    printf("PEM 공개키 크기 : %ld\n", filesize);

    // 길이 먼저 전송 (int로)
    int len = (int)filesize;
    if (send(sockfd, &len, sizeof(int), 0) != sizeof(int)) {
        perror("길이 전송 실패");
        free(buf);
        return -18;
    }

    // PEM 텍스트 그대로 전송
    if (send(sockfd, buf, len, 0) != len) {
        perror("데이터 전송 실패");
        free(buf);
        return -19;
    }

    free(buf);
    return 0;
}
