//client.c
#include "common.h"

int main(int argc, char *argv[]) {
    
    int sockfd;
    struct sockaddr_in server_addr;
    
    while(1){
        
        // 1. 소켓 생성
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd == -1){perror("socket"); exit(1);}

    
        //접속할 서버 주소: 
        //포트번호 : 
        char server_ip[BUFFER_SIZE]; 
        char port_num[7];
        printf("접속할 서버 주소(종료 : exit): ");
        fgets(server_ip, BUFFER_SIZE, stdin);
        server_ip[strcspn(server_ip, "\n")] = '\0';
        
        if(strcmp(server_ip, "exit") == 0){//exit 프로그램 완전 종료
            break;
        }

        printf("포트번호 :"); //12345 -> server 54321 -> root_ca
        fgets(port_num, 7, stdin);
        port_num[strcspn(port_num, "\n")] = '\0';
    
        // 2. 서버 주소 설정
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(atoi(port_num));
	    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

        // 3. 서버에 연결
        if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
            perror("connect"); close(sockfd); exit(1);}
        printf("[%s:%s 서버에 연결됨]\n", server_ip, port_num);
    
        if(!strcmp(port_num, "12345")){
            //server
            sockfd = clnt_to_serv(sockfd);
        }else if(!strcmp(port_num, "54321")){
            //root_ca
            sockfd = client_to_ca(sockfd);
        }
    //종료
    close(sockfd);
    }
}