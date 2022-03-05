/*
 * socket-client.c
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

int main(int argc, char *argv[])
{
	int sd, port;
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	if (port < 1024) //no well known ports can be used for this exercise
	{
		perror("forbidden port");
		exit(0);
	}

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {   //returns a hostent struct
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */

	//fill sockaddr_in struct
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port); //host to network byte order
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));  //struct in_addr
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	getorsend(sd, 1);
	
	if (close(sd) < 0) //close socket
			perror("close");

	fprintf(stderr, "Done.\n");
	return 0;
}
