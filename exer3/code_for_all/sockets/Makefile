###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

all: socket-server socket-client

socket-server: socket-server.c functions.c 
	gcc -Wall -o socket-server socket-server.c functions.c

socket-client: socket-client.c functions.c 
	gcc -Wall -o socket-client socket-client.c functions.c


