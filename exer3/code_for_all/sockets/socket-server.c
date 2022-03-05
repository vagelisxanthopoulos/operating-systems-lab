/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>

#include <sys/ioctl.h>
 
#include <sys/types.h>
#include <sys/stat.h>

//#include <crypto/cryptodev.h>
#include "cryptodev.h"

#include "socket-common.h"

int main(void)
{
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	socklen_t len;
	struct sockaddr_in sa;
	
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { //we dont need "sa" anymore so later we will use it to be filled from "accept"
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		//fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) { //accept fills "sa" with the data of the first client waiting in queue
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) { //convert ip address from binary to text
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		/*NOTE: socket connection behaves like two pipes: 
		server has the read end of the first pipe and the write end of the second pipe 
		
		We found that by testing whether the server/client can read what he wrote in the socket, and the result was that 
		he could not*/


		/* We break out of the loop when the remote peer goes away */

		getorsend(newsd, 0);

		/* Make sure we don't leak open files */
		if (close(newsd) < 0) //close client socket
			perror("close");

		if (close(sd) < 0) //close server socket
			perror("close");

		break; //don't want to accept new connections
	}

	/* This will never happen */
	return 0;
}

